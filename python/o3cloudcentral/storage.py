"""MariaDB/MySQL persistence with normalized ownership and atomic state changes.

Domain metadata is retained losslessly per record during migration. Services,
terminal grants and enrollment tickets have separate indexed relational tables.
No runtime JSON-file or SQLite fallback is provided.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeVar

from sqlalchemy import (BigInteger, Column, ForeignKey, ForeignKeyConstraint,
                        Integer, JSON, MetaData, String, Table, UniqueConstraint,
                        create_engine, delete, insert, inspect, select, text, update)
from sqlalchemy.engine import Connection, make_url

T = TypeVar("T")
SCHEMA_VERSION = 1
metadata = MetaData()
TABLE_OPTIONS = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_bin"}

schema = Table("o3cloudcentral_schema", metadata, Column("id", Integer, primary_key=True),
               Column("version", Integer, nullable=False), **TABLE_OPTIONS)
settings = Table("o3cloudcentral_settings", metadata,
                 Column("id", Integer, primary_key=True),
                 Column("url", String(2048), nullable=False),
                 Column("admin_hash", String(512), nullable=False),
                 Column("revision", BigInteger, nullable=False),
                 Column("import_digest", String(64)), **TABLE_OPTIONS)
sites = Table("o3cloudcentral_sites", metadata,
              Column("id", String(64), primary_key=True),
              Column("name", String(120), nullable=False),
              Column("endpoint", String(320), nullable=False),
              Column("gateway_hash", String(64), index=True),
              Column("data", JSON, nullable=False), **TABLE_OPTIONS)
services = Table("o3cloudcentral_services", metadata,
                 Column("id", String(64), primary_key=True),
                 Column("site_id", String(64), ForeignKey("o3cloudcentral_sites.id", ondelete="CASCADE"), nullable=False, index=True),
                 Column("name", String(120), nullable=False),
                 Column("target", String(45), nullable=False),
                 Column("port", Integer, nullable=False),
                 Column("local_port", Integer, nullable=False),
                 Column("data", JSON, nullable=False),
                 UniqueConstraint("id", "site_id", name="uq_o3cloudcentral_service_site"), **TABLE_OPTIONS)
devices = Table("o3cloudcentral_devices", metadata,
                Column("id", String(64), primary_key=True),
                Column("site_id", String(64), ForeignKey("o3cloudcentral_sites.id", ondelete="CASCADE"), nullable=False, index=True),
                Column("name", String(253), nullable=False),
                Column("data", JSON, nullable=False),
                UniqueConstraint("id", "site_id", name="uq_o3cloudcentral_device_site"), **TABLE_OPTIONS)
grants = Table("o3cloudcentral_device_services", metadata,
               Column("device_id", String(64), primary_key=True),
               Column("service_id", String(64), primary_key=True),
               Column("site_id", String(64), nullable=False),
               Column("position", Integer, nullable=False),
               ForeignKeyConstraint(["device_id", "site_id"], ["o3cloudcentral_devices.id", "o3cloudcentral_devices.site_id"], ondelete="CASCADE", name="fk_o3cloudcentral_grant_device"),
               ForeignKeyConstraint(["service_id", "site_id"], ["o3cloudcentral_services.id", "o3cloudcentral_services.site_id"], ondelete="CASCADE", name="fk_o3cloudcentral_grant_service"), **TABLE_OPTIONS)
reports = Table("o3cloudcentral_gateway_reports", metadata,
                Column("site_id", String(64), ForeignKey("o3cloudcentral_sites.id", ondelete="CASCADE"), primary_key=True),
                Column("data", JSON, nullable=False), **TABLE_OPTIONS)
tickets = Table("o3cloudcentral_tickets", metadata,
                Column("hash", String(64), primary_key=True),
                Column("kind", String(32), nullable=False),
                Column("object_id", String(64), nullable=False),
                Column("site_id", String(64), ForeignKey("o3cloudcentral_sites.id", ondelete="CASCADE"), nullable=False, index=True),
                Column("data", JSON, nullable=False), **TABLE_OPTIONS)



auth_users = Table("o3cloudcentral_auth_users", metadata,
                   Column("id", String(64), primary_key=True),
                   Column("data", JSON, nullable=False), **TABLE_OPTIONS)
auth_sessions = Table("o3cloudcentral_auth_sessions", metadata,
                      Column("id", String(64), primary_key=True),
                      Column("data", JSON, nullable=False), **TABLE_OPTIONS)


def empty_state() -> dict:
    return {"url": "", "admin_hash": "", "sites": {}, "devices": {}, "tickets": {}}


def validate_state(state: dict) -> None:
    if not isinstance(state, dict) or not {"url", "admin_hash", "sites", "devices", "tickets"} <= set(state) or set(state) - {"url", "admin_hash", "sites", "devices", "tickets", "users", "sessions"}:
        raise ValueError("Estrutura de estado incompatível.")
    if not isinstance(state["url"], str) or not isinstance(state["admin_hash"], str):
        raise ValueError("Configuração da central inválida.")
    for key in ("sites", "devices", "tickets"):
        if not isinstance(state[key], dict):
            raise ValueError("Coleção inválida no estado.")
    users, sessions = state.get("users", {}), state.get("sessions", {})
    if not isinstance(users, dict) or not isinstance(sessions, dict) or len(users) > 256 or len(sessions) > 4096:
        raise ValueError("Coleção de autenticação inválida.")
    for username, account in users.items():
        if (not isinstance(username, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", username) or username == "admin"
                or not isinstance(account, dict) or set(account) != {"password_hash", "created"}
                or not isinstance(account["password_hash"], str) or not account["password_hash"].startswith("scrypt$")
                or len(account["password_hash"]) > 512 or not isinstance(account["created"], str)):
            raise ValueError("Usuário inválido.")
    for hashed, session in sessions.items():
        if (not isinstance(hashed, str) or not re.fullmatch(r"[0-9a-f]{64}", hashed) or not isinstance(session, dict)
                or set(session) != {"username", "expires", "credential"}
                or session.get("username") not in {"admin", *users}
                or not re.fullmatch(r"[0-9a-f]{64}", str(session.get("credential", "")))):
            raise ValueError("Sessão inválida.")
        try:
            expiry = datetime.fromisoformat(session["expires"].replace("Z", "+00:00"))
            if expiry.tzinfo is None: raise ValueError()
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ValueError("Validade de sessão inválida.") from None
    service_owners = {}
    for identifier, site in state["sites"].items():
        if not isinstance(site, dict) or identifier != site.get("id") or not 1 <= len(identifier) <= 64:
            raise ValueError("Identidade de cliente inválida.")
        for service in site.get("services") or []:
            sid = service.get("id", "")
            if not sid or len(sid) > 64 or sid in service_owners:
                raise ValueError("Identidade de serviço duplicada.")
            service_owners[sid] = identifier
    for identifier, device in state["devices"].items():
        if identifier != device.get("id") or not 1 <= len(identifier) <= 64 or device.get("site_id") not in state["sites"]:
            raise ValueError("Terminal sem cliente válido.")
        allowed = device.get("services") or []
        if len(set(allowed)) != len(allowed) or any(service_owners.get(sid) != device["site_id"] for sid in allowed):
            raise ValueError("Permissão de terminal pertence a outro cliente ou serviço removido.")
    link_sites, link_ids = set(), set()
    for hashed, ticket in state["tickets"].items():
        kind = ticket.get("kind")
        if len(hashed) != 64 or hashed != ticket.get("hash") or kind not in ("agent", "gateway", "gateway-update", "gateway-reinstall", "agent-link"):
            raise ValueError("Cadastro temporário inválido.")
        owners = state["devices"] if kind == "agent" else state["sites"]
        if ticket.get("object_id") not in owners:
            raise ValueError("Cadastro temporário órfão.")
        if kind == "agent-link":
            allowed_fields = {"hash", "kind", "object_id", "id", "services", "created", "expires", "used_count", "platform"}
            identifier, selected = ticket.get("id"), ticket.get("services")
            if set(ticket) - allowed_fields or not isinstance(identifier, str) or not re.fullmatch(r"lnk_[0-9a-f]{24}", identifier) or identifier in link_ids:
                raise ValueError("Identidade de link de instalação inválida.")
            link_ids.add(identifier)
            site_id = ticket["object_id"]
            link_platform = ticket.get('platform', 'windows')
            if link_platform not in ('windows','debian'):
                raise ValueError('Sistema operacional do link inválido.')
            if not isinstance(selected, list) or not 1 <= len(selected) <= 64 or any(not isinstance(sid, str) for sid in selected) or len(set(selected)) != len(selected) or any(service_owners.get(sid) != site_id for sid in selected):
                raise ValueError("Serviços do link pertencem a outro cliente ou foram removidos.")
            ports = [service["local_port"] for service in state["sites"][site_id].get("services") or [] if service["id"] in selected]
            if len(set(ports)) != len(ports):
                raise ValueError("Serviços do link usam portas locais conflitantes.")
            if type(ticket.get("used_count")) is not int or ticket["used_count"] < 0:
                raise ValueError("Contagem de instalações inválida.")
            try:
                created = datetime.fromisoformat(ticket["created"].replace("Z", "+00:00"))
                if created.tzinfo is None:
                    raise ValueError
                expires = ticket.get("expires")
                deadline = None if expires in (None, "") else datetime.fromisoformat(expires.replace("Z", "+00:00"))
                if deadline is not None and deadline.tzinfo is None:
                    raise ValueError
            except (ValueError, AttributeError, KeyError, TypeError):
                raise ValueError("Datas do link de instalação inválidas.") from None
            active = deadline is None or deadline > datetime.now(timezone.utc)
            if active and (site_id, link_platform) in link_sites:
                raise ValueError("Já existe um link de instalação ativo para este cliente.")
            if active:
                link_sites.add((site_id, link_platform))


class StateRepository:
    def __init__(self, dsn: str):
        parsed = make_url(dsn)
        if parsed.get_backend_name() not in ("mysql", "mariadb") or not parsed.database:
            raise ValueError("Configure uma URL MariaDB/MySQL; outros bancos não são usados.")
        if parsed.drivername not in ("mysql+pymysql", "mariadb+pymysql"):
            raise ValueError("Use mysql+pymysql:// ou mariadb+pymysql://.")
        self.engine = create_engine(dsn, pool_pre_ping=True, pool_recycle=1800,
                                    isolation_level="READ COMMITTED",
                                    connect_args={"connect_timeout": 10, "read_timeout": 20, "write_timeout": 20})
        self._migration_lock = "o3cloudcentral-schema-" + hashlib.sha256(parsed.database.encode()).hexdigest()[:32]

    def initialize_schema(self) -> None:
        with self.engine.connect() as conn:
            if conn.execute(text("SELECT GET_LOCK(:name, 30)"), {"name": self._migration_lock}).scalar() != 1:
                raise RuntimeError("Outra migração do banco está em andamento.")
            try:
                existing = inspect(conn).get_table_names()
                if any(name.endswith("_settings") and name != settings.name for name in existing):
                    raise RuntimeError("Esquema anterior detectado. Execute a migração antes de iniciar a central.")
                metadata.create_all(conn)
                conn.commit()
                row = conn.execute(select(schema.c.version).where(schema.c.id == 1)).scalar()
                if row not in (None, SCHEMA_VERSION):
                    raise RuntimeError("Versão do banco incompatível; faça a migração antes de iniciar.")
                if row is None:
                    conn.execute(insert(schema).values(id=1, version=SCHEMA_VERSION))
                if conn.execute(select(settings.c.id).where(settings.c.id == 1)).scalar() is None:
                    conn.execute(insert(settings).values(id=1, url="", admin_hash="", revision=0))
                conn.commit()
            finally:
                conn.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": self._migration_lock})
                conn.commit()

    def close(self) -> None:
        self.engine.dispose()

    def read(self) -> dict:
        with self.engine.begin() as conn:
            # Lock also protects consistent multi-table reads across workers.
            header = conn.execute(select(settings).where(settings.c.id == 1).with_for_update()).mappings().first()
            if header is None:
                raise RuntimeError("Banco não inicializado.")
            return self._load(conn, header)

    def transaction(self, operation: Callable[[dict], T]) -> T:
        with self.engine.begin() as conn:
            header = conn.execute(select(settings).where(settings.c.id == 1).with_for_update()).mappings().first()
            if header is None:
                raise RuntimeError("Banco não inicializado.")
            previous = self._load(conn, header)
            state = copy.deepcopy(previous)
            result = operation(state)
            validate_state(state)
            self._persist(conn, previous, state)
            conn.execute(update(settings).where(settings.c.id == 1).values(
                url=state["url"], admin_hash=state["admin_hash"], revision=header["revision"] + 1))
            # The caller cannot accidentally mutate data after commit.
            return copy.deepcopy(result)

    def initialize(self, state: dict) -> None:
        def install(current):
            if current != empty_state():
                raise ValueError("Banco já contém cadastros; inicialização cancelada.")
            current.clear()
            current.update(copy.deepcopy(state))
        self.transaction(install)

    def import_legacy(self, path: str | Path, *, dry_run: bool = False) -> dict:
        raw = Path(path).read_bytes()
        imported = json.loads(raw)
        validate_state(imported)
        if not imported["url"] or not imported["admin_hash"]:
            raise ValueError("Arquivo não pertence a uma central inicializada.")
        fingerprint = hashlib.sha256(raw).hexdigest()
        summary = {"sites": len(imported["sites"]), "devices": len(imported["devices"]),
                   "services": sum(len(s.get("services") or []) for s in imported["sites"].values()),
                   "tickets": len(imported["tickets"]), "dry_run": dry_run}
        if dry_run:
            return summary
        with self.engine.begin() as conn:
            header = conn.execute(select(settings).where(settings.c.id == 1).with_for_update()).mappings().one()
            if header["import_digest"] == fingerprint:
                return {**summary, "already_imported": True}
            previous = self._load(conn, header)
            if previous != empty_state() or header["import_digest"]:
                raise ValueError("Destino não está vazio; importação recusada para preservar os cadastros.")
            self._persist(conn, previous, imported)
            conn.execute(update(settings).where(settings.c.id == 1).values(
                url=imported["url"], admin_hash=imported["admin_hash"], revision=header["revision"]+1, import_digest=fingerprint))
            # Reconstruct inside the same transaction: a mismatch rolls back.
            after = self._load(conn, {**header, "url": imported["url"], "admin_hash": imported["admin_hash"]})
            if after != imported:
                raise RuntimeError("A conferência da migração falhou; nenhuma alteração foi confirmada.")
        return {**summary, "already_imported": False}

    def _load(self, conn: Connection, header) -> dict:
        state = {"url": header["url"], "admin_hash": header["admin_hash"], "sites": {}, "devices": {}, "tickets": {}}
        for row in conn.execute(select(sites)).mappings():
            state["sites"][row["id"]] = copy.deepcopy(row["data"])
        ordered_services = sorted(conn.execute(select(services)).mappings(), key=lambda r: (r["site_id"], r["data"].get("_o3cloudcentral_position", 0)))
        for row in ordered_services:
            data = copy.deepcopy(row["data"])
            data.pop("_o3cloudcentral_position", None)
            state["sites"][row["site_id"]].setdefault("services", []).append(data)
        for row in conn.execute(select(reports)).mappings():
            state["sites"][row["site_id"]]["report"] = copy.deepcopy(row["data"])
        for row in conn.execute(select(devices)).mappings():
            state["devices"][row["id"]] = copy.deepcopy(row["data"])
        for row in conn.execute(select(grants).order_by(grants.c.device_id, grants.c.position)).mappings():
            state["devices"][row["device_id"]].setdefault("services", []).append(row["service_id"])
        for row in conn.execute(select(tickets)).mappings():
            state["tickets"][row["hash"]] = copy.deepcopy(row["data"])
        for table, key in ((auth_users, "users"), (auth_sessions, "sessions")):
            values = {row["id"]:copy.deepcopy(row["data"]) for row in conn.execute(select(table)).mappings()}
            if values: state[key] = values
        return state

    @staticmethod
    def _records(state: dict) -> dict:
        result = {table.name: {} for table in (sites, services, devices, grants, reports, tickets, auth_users, auth_sessions)}
        for sid, site in state["sites"].items():
            data = copy.deepcopy(site)
            service_list = data.pop("services", None)
            # Preserve [] vs null for exact legacy import verification.
            data["services"] = [] if service_list is not None else None
            report = data.pop("report", None)
            result[sites.name][sid] = dict(id=sid, name=site["name"], endpoint=site["endpoint"], gateway_hash=site.get("gateway_hash") or None, data=data)
            if report is not None:
                result[reports.name][sid] = dict(site_id=sid, data=report)
            for position, service in enumerate(service_list or []):
                value = copy.deepcopy(service)
                value["_o3cloudcentral_position"] = position
                result[services.name][service["id"]] = dict(id=service["id"], site_id=sid, name=service["name"], target=service["target"], port=service["port"], local_port=service["local_port"], data=value)
        for did, device in state["devices"].items():
            value = copy.deepcopy(device)
            allowed = value.pop("services", None)
            value["services"] = [] if allowed is not None else None
            result[devices.name][did] = dict(id=did, site_id=device["site_id"], name=device["name"], data=value)
            for position, sid in enumerate(allowed or []):
                result[grants.name][(did, sid)] = dict(device_id=did, service_id=sid, site_id=device["site_id"], position=position)
        for hashed, ticket in state["tickets"].items():
            sid = state["devices"][ticket["object_id"]]["site_id"] if ticket["kind"] == "agent" else ticket["object_id"]
            result[tickets.name][hashed] = dict(hash=hashed, kind=ticket["kind"], object_id=ticket["object_id"], site_id=sid, data=copy.deepcopy(ticket))
        for table, key in ((auth_users, "users"), (auth_sessions, "sessions")):
            for identifier, value in state.get(key, {}).items():
                result[table.name][identifier] = dict(id=identifier, data=copy.deepcopy(value))
        return result

    @staticmethod
    def _where(table, key):
        if table is grants:
            return (table.c.device_id == key[0]) & (table.c.service_id == key[1])
        return table.c[{"o3cloudcentral_gateway_reports": "site_id", "o3cloudcentral_tickets": "hash"}.get(table.name, "id")] == key

    def _persist(self, conn: Connection, previous: dict, current: dict) -> None:
        old, new = self._records(previous), self._records(current)
        for table in (auth_sessions, auth_users, grants, tickets, reports, devices, services, sites):
            for key in old[table.name].keys() - new[table.name].keys():
                conn.execute(delete(table).where(self._where(table, key)))
        for table in (sites, services, devices, reports, grants, tickets, auth_users, auth_sessions):
            for key, values in new[table.name].items():
                before = old[table.name].get(key)
                if before is None:
                    conn.execute(insert(table).values(**values))
                elif before != values:
                    conn.execute(update(table).where(self._where(table, key)).values(**values))
