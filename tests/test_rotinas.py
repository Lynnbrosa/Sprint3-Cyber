"""Rotinas de seguranca continua: auditoria de permissoes."""
from tests.conftest import login


def test_auditoria_aponta_conta_inativa_e_quem_tentou_fora_do_papel(client, usuarios, db):
    from app.cli.auditoria_permissoes import gerar

    login(client, "admin")
    consultor = login(client, "consultor")
    client.get("/v1/admin/audit-log", headers={"Authorization": f"Bearer {consultor['access_token']}"})

    relatorio, pendencias = gerar(db, dias_inativo=90)
    assert "analista@ford.com: inativo" in "\n".join(pendencias)
    assert "consultor@ford.com: tentou acesso fora do papel" in "\n".join(pendencias)
    assert not any(p.startswith("admin@ford.com") for p in pendencias)
    assert "| consultor@ford.com | consultor |" in relatorio
