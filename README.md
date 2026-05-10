# 🛡 Sentinel360 v2 – Cyber Defense Platform

Sistema de **governança e detecção de riscos de dados** para ambientes corporativos.
Detecta arquivos inativos, credenciais expostas e PII (CPF, cartões, chaves privadas) em qualquer máquina da empresa.

---

## Arquitetura

```
┌──────────────────────────────────────────────────────┐
│                 Frontend (React + Vite)               │
│  Dashboard · ScanControl · Alerts · Office365        │
└───────────────────┬──────────────────────────────────┘
                    │  HTTPS / JWT
┌───────────────────▼──────────────────────────────────┐
│              Backend (FastAPI + Python)               │
│  Auth · Scans · Results · Alerts · Office365 API     │
│  ┌────────────────┐  ┌──────────────────────────┐    │
│  │  AI Detector   │  │   Notifier               │    │
│  │  (Claude API)  │  │   Email · Webhook · Slack│    │
│  └────────────────┘  └──────────────────────────┘    │
└───────────────────┬──────────────────────────────────┘
                    │  MongoDB (Atlas / local)
┌───────────────────▼──────────────────────────────────┐
│            Agente Remoto (Python CLI)                 │
│  Roda em qualquer Windows/Linux/macOS                 │
│  Varre arquivos → envia resultados em batches         │
│  Pode rodar como serviço (systemd / Windows Service)  │
└──────────────────────────────────────────────────────┘
```

---

## Setup rápido

### 1. Backend

```bash
cd backend/
pip install -r requirements.txt

# Configure variáveis de ambiente
cp .env.example .env
# Edite .env com suas credenciais MongoDB e ANTHROPIC_API_KEY

python server.py
# API disponível em http://localhost:8000
# Docs: http://localhost:8000/docs
```

### 2. Frontend (já existente no Sentinel360Frontend)

Substitua os componentes:
```bash
# Copie os novos componentes para src/app/components/
cp frontend_components/*.tsx ../Sentinel360Frontend/src/app/components/

# Atualize as variáveis de ambiente
echo "VITE_API_URL=https://sentinel360.onrender.com" > ../Sentinel360Frontend/.env
```

### 3. Agente Remoto

**Instalação na máquina a monitorar:**
```bash
pip install sentinel360-agent/

# Configure o agente (gere a API key no dashboard primeiro)
s360-agent install \
  --api-url https://sentinel360.onrender.com \
  --agent-key s360_SUA_CHAVE_AQUI \
  --user-token SEU_JWT_TOKEN \
  --days 180 \
  --interval 60

# Executar um scan agora
s360-agent run

# Instalar como serviço (roda automaticamente)
s360-service install
```

---

## Funcionalidades v2

### ✅ Implementado nesta versão

| Módulo | Funcionalidade |
|--------|---------------|
| **Multi-tenant** | Organizações, roles (owner/admin/analyst/viewer), usuários por org |
| **Agente remoto** | Instalável via pip, varre qualquer máquina, envia em batches |
| **Detecção por IA** | Claude API classifica PII com confiança + tipo (graceful degradation sem key) |
| **Office 365** | Usuários inativos no Azure AD, arquivos compartilhados externamente |
| **Alertas** | Disparo por e-mail + Webhook + Slack para riscos critical/high |
| **Dashboard** | Métricas em tempo real, gráficos, top riscos, status de agentes |
| **API REST** | Completa com autenticação JWT, paginação, filtros por risk_level |

### 🔜 Próximas fases sugeridas

- **Exportação PDF** de relatórios (com gráficos)
- **Agendamento de scans** via cron no backend
- **Remediação assistida**: botão para mover arquivo para quarentena
- **SIEM integration**: forward de eventos para Splunk/Elastic
- **Scan de SharePoint/OneDrive** via Graph API

---

## Estrutura do projeto

```
sentinel360/
├── backend/
│   ├── server.py              # FastAPI principal (routers, endpoints)
│   ├── requirements.txt
│   ├── core/
│   │   ├── database.py        # MongoDB async (motor) – multi-tenant
│   │   └── auth.py            # JWT + roles + agent key auth
│   ├── models/
│   │   └── models.py          # Pydantic models (Org, User, Agent, Scan, Result, Alert)
│   └── services/
│       ├── ai_detector.py     # Detecção PII (regex + Claude API)
│       ├── notifier.py        # Email + Webhook + Slack
│       └── office365.py       # Microsoft Graph API
├── agent/
│   ├── agent.py               # CLI instalável (s360-agent)
│   ├── service_installer.py   # Daemon systemd / Windows Service / launchd
│   └── setup.py               # pip package
└── frontend_components/
    ├── Dashboard.tsx           # Dashboard com métricas reais
    ├── ScanControl.tsx         # Painel de controle + agentes
    ├── AlertsPage.tsx          # Alertas + tabela de resultados
    └── Office365Page.tsx       # Integração Azure AD
```

---

## Variáveis de ambiente

| Variável | Obrigatório | Descrição |
|----------|-------------|-----------|
| `MONGO_URL` | ✅ | Connection string MongoDB |
| `DB_NAME` | ✅ | Nome do banco (default: sentinel360) |
| `SECRET_KEY` | ✅ | Segredo JWT (gere com `python -c "import secrets; print(secrets.token_hex(32))"`) |
| `ANTHROPIC_API_KEY` | ⚪ | Ativa detecção por IA (sem ela usa só regex) |
| `SMTP_HOST` | ⚪ | Servidor SMTP para alertas por e-mail |
| `SMTP_USER` | ⚪ | Usuário SMTP |
| `SMTP_PASS` | ⚪ | Senha SMTP |
| `ALLOWED_ORIGINS` | ⚪ | URLs do frontend (separadas por vírgula) |

---

## Permissões necessárias no Azure AD

Para a integração Office 365, o app registrado precisa de:

| Permissão | Tipo | Motivo |
|-----------|------|--------|
| `User.Read.All` | Application | Listar todos os usuários |
| `Directory.Read.All` | Application | Ler grupos e estrutura do AD |
| `AuditLog.Read.All` | Application | Verificar último login |
| `UserAuthenticationMethod.Read.All` | Application | Verificar MFA (opcional) |

---

## Segurança

- Senhas armazenadas com **bcrypt** (custo 12)
- Tokens JWT com expiração configurável (padrão 24h)
- API keys de agentes geradas com `secrets.token_urlsafe(36)` (256+ bits)
- Campos sensíveis (client_secret, api_key) nunca retornados em listagens
- Multi-tenant: todas as queries filtradas por `org_id`
- Snippets de PII exibidos ofuscados (nunca o dado real)
