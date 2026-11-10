"""Interface web (Streamlit) do Identificador de Publicidade Sexista (Observatório da Publicidade Não Sexista, OPeNS).

Variáveis de ambiente / secrets:
  ANTHROPIC_API_KEY   (obrigatória)
  APP_ACCESS_CODE     (recomendada: código de acesso, evita uso indevido da sua chave de API)
  DATABASE_URL        (opcional: se definida, habilita o armazenamento com consentimento)
  OPENS_SALT          (obrigatória se DATABASE_URL for usada: pseudonimização de usuários)
  OPENS_CONTATO_PRIVACIDADE, OPENS_RETENCAO_DIAS, OPENS_PASTA_MIDIAS (opcionais)
"""
import hmac
import os
import tempfile
from pathlib import Path

import anthropic
import streamlit as st

import opens_auditor as oa


def _carregar_segredos() -> None:
    """Disponibiliza os Secrets do Streamlit como variáveis de ambiente (sem sobrescrever as já definidas)."""
    try:
        for chave, valor in st.secrets.items():
            if isinstance(valor, (str, int, float)) and chave not in os.environ:
                os.environ[chave] = str(valor).strip()
    except Exception:
        pass  # sem secrets (execução local): usa só as variáveis de ambiente


_carregar_segredos()

RETENCAO = int(os.environ.get("OPENS_RETENCAO_DIAS", oa.RETENCAO_PADRAO_DIAS))
PASTA = Path(os.environ.get("OPENS_PASTA_MIDIAS", "base_opens"))
ARMAZENAMENTO_ATIVO = bool(os.environ.get("DATABASE_URL"))
CONTATO = os.environ.get("OPENS_CONTATO_PRIVACIDADE", "o responsável pela ferramenta")
QUADROS = 8

st.set_page_config(page_title="Identificador de Publicidade Sexista", page_icon="🔎", layout="centered")


def _logo() -> None:
    """Mostra o logotipo do OPeNS acima do título, se o arquivo estiver no repositório
    (logo_opens.png, .jpg, .jpeg ou .webp, na mesma pasta do app.py)."""
    for nome in ("logo_opens.png", "logo_opens.jpg", "logo_opens.jpeg", "logo_opens.webp"):
        caminho = Path(__file__).parent / nome
        if caminho.exists():
            st.image(str(caminho), width=240)
            return


_logo()
st.title("Identificador de Publicidade Sexista")
st.markdown("**Observatório da Publicidade Não Sexista (OPeNS)**")
st.caption("Triagem de peças publicitárias com base nos 12 critérios do Observatório da "
           "Publicidade Não Sexista (OPeNS / Fatec).")

# --- Controle de acesso (protege o custo da API) ---------------------------------
codigo = os.environ.get("APP_ACCESS_CODE")
if codigo:
    digitado = st.text_input("Código de acesso", type="password")
    if not digitado:
        st.stop()
    if not hmac.compare_digest(digitado.encode(), codigo.encode()):
        st.error("Código de acesso inválido.")
        st.stop()


if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
    st.error(
        "A chave da API não está configurada. No Streamlit, abra Manage app > Settings > Secrets e "
        "acrescente a linha:  ANTHROPIC_API_KEY = \"sua-chave\"  (com aspas, no começo da linha, "
        "sem [seção] antes). Salve e reinicie o app."
    )
    st.stop()


@st.cache_resource
def cliente() -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"].strip())


@st.cache_resource
def expurgo_diario():
    """Exclui dados vencidos 1x por dia, dentro do próprio serviço.

    Necessário porque, na Render, o disco das mídias só é acessível pelo serviço web
    (um cron job separado não enxerga esse disco).
    """
    if not ARMAZENAMENTO_ATIVO:
        return None
    import threading
    import time

    def laco():
        while True:
            try:
                con = oa.conectar_base(PASTA)
                oa.purgar(con)
                con.close()
            except Exception:
                pass  # tenta de novo no próximo ciclo
            time.sleep(24 * 3600)

    t = threading.Thread(target=laco, daemon=True)
    t.start()
    return t


expurgo_diario()


def mostrar(r: dict) -> None:
    st.divider()
    if "erro" in r:
        st.error(f"Não foi possível concluir a análise: {r['erro']}")
    else:
        resultado = r.get("resultado", "")
        if resultado == "suspeito":
            st.warning("Resultado: **SUSPEITO** — requer revisão humana.")
        elif resultado == "não suspeito":
            st.success("Resultado: **NÃO SUSPEITO**")
        else:
            st.info(f"Resultado: **{resultado.upper()}**")
        if r.get("criterios_acionados"):
            st.markdown("**Critérios acionados**")
            for c in r["criterios_acionados"]:
                st.markdown(f"- {c}")
        st.markdown(f"**Justificativa:** {r.get('justificativa', '')}")
        if r.get("pessoas"):
            st.markdown(f"**Pessoas identificadas:** {r.get('quantidade_pessoas', len(r['pessoas']))}")
            st.table(r["pessoas"])
        if r.get("corpo_feminino_exposto") or r.get("menores_com_exposicao"):
            nec = r.get("corpo_necessario_para_produto")
            rotulo = {True: "necessária para o produto/serviço",
                      False: "desconectada do produto/serviço"}.get(nec, "relação com o produto não avaliada")
            quem = "Menor de idade com exposição" if r.get("menores_com_exposicao") else "Corpo feminino exposto"
            st.caption(f"{quem} identificado(a) — exposição {rotulo}.")
    # o aviso de limitações aparece sempre, inclusive nos erros
    st.info(r.get("avisos_e_limitacoes", ""))
    if "id_base" in r:
        st.caption(f"Material e análise armazenados (retenção de {RETENCAO} dias). "
                   "Para excluir, use a seção \"Excluir meus dados\" abaixo.")
    # site do OPeNS: última linha da mensagem de análise (antes do detalhe técnico)
    st.markdown(f"Saiba mais sobre o Observatório da Publicidade Não Sexista (OPeNS): "
                f"[{oa.SITE_OPENS}]({oa.SITE_OPENS})")
    with st.expander("JSON completo"):
        st.json(r)


# --- Privacidade e consentimento ---------------------------------------------------
with st.expander("Aviso de privacidade (LGPD)"):
    st.text(oa.aviso_privacidade(RETENCAO))

consentimento = False
usuario = ""
if ARMAZENAMENTO_ATIVO:
    consentimento = st.checkbox(
        "Li o aviso e autorizo o armazenamento do material e da análise para fins de pesquisa. "
        "(Opcional: sem esta autorização a análise é feita, mas nada é guardado.)")
    usuario = st.text_input("Identificação (opcional — gravada apenas como hash)")
else:
    st.caption("Armazenamento desativado: o material enviado é analisado e descartado.")

# --- Entrada ---------------------------------------------------------------------
tipos = sorted(e.lstrip(".") for e in oa.EXT_IMAGEM | oa.EXT_VIDEO)
arquivo = st.file_uploader("Imagem ou vídeo", type=tipos)
link = st.text_input("...ou link direto para uma imagem/vídeo (https://...)").strip()

if st.button("Analisar", type="primary", disabled=not (arquivo or link)):
    with tempfile.TemporaryDirectory() as tmp, st.spinner("Analisando... vídeos podem levar alguns minutos."):
        itens = []
        if arquivo:
            # nome fixo: o nome original do arquivo do usuário nunca é usado nem gravado
            caminho = Path(tmp) / f"upload{Path(arquivo.name).suffix.lower()}"
            caminho.write_bytes(arquivo.getbuffer())
            itens.append(("arquivo", None, caminho))
        if link:
            itens.append(("link", link, None))

        con = usuario_hash = None
        if consentimento:
            try:
                usuario_hash = oa.pseudonimizar(usuario)
                con = oa.conectar_base(PASTA)
                oa.purgar(con)
            except Exception as e:
                con = None
                st.warning(f"Armazenamento indisponível ({e}). A análise será feita sem gravar.")

        for origem, lk, arq in itens:
            nota = None
            try:
                if origem == "link":
                    arq, nota = oa.baixar_link(lk, Path(tmp))
                r = oa.analisar(arq, cliente(), oa.MODELO_PADRAO, QUADROS, None, nota)
            except Exception as e:
                ext = arq.suffix.lower() if arq else ""
                tipo = "video" if ext in oa.EXT_VIDEO else "imagem" if ext in oa.EXT_IMAGEM else None
                r = oa.anexar_avisos({"erro": str(e)}, tipo, QUADROS, False, nota)
            if con is not None:
                try:
                    oa.registrar(con, PASTA, origem, lk, arq, r, usuario_hash, RETENCAO)
                except Exception as e:
                    st.warning(f"Não foi possível armazenar este item ({e}).")
            mostrar(r)

# --- Direito de exclusão ---------------------------------------------------------
if ARMAZENAMENTO_ATIVO:
    with st.expander("Excluir meus dados"):
        st.write("Apaga todo o material e as análises enviados com a identificação informada. "
                 f"Dúvidas ou outros pedidos: {CONTATO}.")
        quem = st.text_input("Identificação usada nos envios", key="excluir_quem")
        if st.button("Excluir", disabled=not quem.strip()):
            try:
                n = oa.excluir(oa.conectar_base(PASTA), usuario_hash=oa.pseudonimizar(quem))
                st.success(f"{n} registro(s) excluído(s).")
            except Exception as e:
                st.error(f"Não foi possível excluir: {e}")
