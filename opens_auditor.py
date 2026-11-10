#!/usr/bin/env python3
"""
Auditor OPeNS — verifica imagens e vídeos segundo os 12 critérios do
Observatório de Publicidade Não Sexista (OPeNS / Fatec).

Pipeline em 2 etapas:
  1. Análise visual  -> descrição objetiva e neutra (Claude Vision, ou texto
                        vindo de outro VLM, ex.: VLM Run, via --descricao-vlm)
  2. Auditoria OPeNS -> prompt estruturado, saída em JSON validado

Uso:
  python opens_auditor.py anuncio.jpg
  python opens_auditor.py comercial.mp4 --frames 10
  python opens_auditor.py anuncio.jpg --descricao-vlm descricao_vlmrun.txt
  python opens_auditor.py pasta_com_arquivos/ --saida resultados.json
  python opens_auditor.py --link https://site.com/anuncio.jpg --usuario maria --consentimento
  python opens_auditor.py --listar            # últimas submissões da base

Armazenamento (PostgreSQL + pasta de mídias) e privacidade (LGPD):
  * Variáveis de ambiente: DATABASE_URL (postgresql://usuario:senha@host:5432/opens),
    OPENS_SALT (segredo para pseudonimizar usuários) e OPENS_CONTATO_PRIVACIDADE.
  * Nada é armazenado sem --consentimento (a interface que chama a ferramenta deve
    ter coletado o aceite do usuário). Sem ele, a análise é feita mas não é gravada.
  * Minimização: usuário vira hash (HMAC); links são gravados sem query string/
    credenciais; mídias com pessoas aparentemente menores de idade NÃO são retidas
    (só a análise); mídias idênticas são guardadas uma única vez (SHA-256).
  * Retenção: 180 dias por padrão (--retencao-dias); expurgo automático a cada uso
    com gravação e manual com --purgar.
  * Direitos do titular: --excluir ID / --excluir-usuario NOME apagam registros e
    mídias. --privacidade mostra o aviso de privacidade.

Requisitos: pip install anthropic opencv-python
Variável de ambiente: ANTHROPIC_API_KEY
"""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import html
import io
import ipaddress
import json
import mimetypes
import os
import re
import shutil
import socket
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import anthropic
import psycopg
from psycopg.types.json import Jsonb

MODELO_PADRAO = "claude-sonnet-5-5"
SITE_OPENS = "https://fatecgarca.cps.sp.gov.br/observatorio/"
EXT_IMAGEM = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif", ".avif"}
EXT_VIDEO = {".mp4", ".mov", ".avi", ".mkv", ".webm"}

# --------------------------------------------------------------------------
# Prompts
# --------------------------------------------------------------------------
PROMPT_DESCRICAO = """Você é um analista visual. Descreva de forma OBJETIVA e NEUTRA o conteúdo \
da(s) imagem(ns) a seguir (se forem vários quadros, são amostras sequenciais de um mesmo vídeo). \
Não julgue, não interprete intenções e não identifique pessoas reais pelo nome.

Descreva, quando houver:
- Número de pessoas; para cada uma: idade aparente (criança / adolescente / adulto jovem / adulto / \
idoso / não identificável), gênero aparente (masculino / feminino / não identificável), \
cor de pele/etnia aparente, tipo corporal, vestuário, pose, expressão facial.
- Ações e papéis (quem faz o quê: servir, cuidar, trabalhar, liderar, obedecer, etc.) e interações \
entre as pessoas (contato físico, agressão, coerção, dependência, resgate).
- Composição familiar ou de grupo aparente.
- Produto ou serviço anunciado (categoria e o que é vendido) e a relação visual entre ele e as \
pessoas/corpos: indique se partes do corpo estão expostas (ex.: roupa de banho, lingerie, nudez, \
roupas curtas ou justas) e se essa exposição tem relação direta com o que está sendo vendido.
- Cenário (lar, trabalho, rua, estúdio...) e estilo (fotografia publicitária, editorial, moda...).
- Todo texto visível (transcreva literalmente), legendas e falas, se houver.
- Para vídeo: a progressão das cenas entre os quadros.

Responda em português, em texto corrido organizado por tópicos curtos."""

PROMPT_AUDITORIA = """Você é um auditor de publicidade especializado nos critérios do Observatório de \
Publicidade Não Sexista (OPeNS) da Fatec. Com base nas características extraídas da imagem/vídeo a \
seguir, faça uma análise estruturada.

【Conteúdo da análise visual】
{descricao}

【ETAPA 1 — Verificação de presença e caracterização de pessoas】
Antes de julgar os critérios, responda obrigatoriamente:
- Há pessoas na imagem/vídeo? (sim/não)
- Se sim, quantas pessoas aparecem?
- Para cada pessoa identificada, informe:
  - Idade aparente (criança / adolescente / adulto jovem / adulto / idoso / não identificável)
  - Gênero aparente (masculino / feminino / não identificável)
- Se NÃO houver pessoas, pule a ETAPA 2 e retorne "não aplicável" nos critérios que dependem de figuras humanas.

【ETAPA 2 — Julgamento dos 12 critérios do OPeNS】
1. Coisificação: O corpo feminino é usado como decoração ou elemento sugestivo, sem relação com o produto.
2. Sexualização de menores: Menores aparecem em poses ou vestuário sugestivos.
3. Estereótipo emocional: Mulheres retratadas como chorosas, histéricas, emocionalmente instáveis.
4. Falta de vontade própria: Mulheres aparecem apenas servindo ou obedecendo aos outros.
5. Padrões de beleza inalcançáveis: Magreza/beleza associada a sucesso ou felicidade.
6. Padrões de beleza únicos: Apenas um tipo de corpo/etnia/idade é representado.
7. Violência: Agressão física, coerção ou textos que banalizam a violência.
8. Inferioridade/dependência: Mulheres retratadas como incapazes, frágeis, necessitando de resgate.
9. Linguagem discriminatória: Uso de termos pejorativos ou excludentes contra mulheres.
10. Ignorar diversidade: Apenas família heterossexual nuclear é representada como norma.
11. Desvalorizar mulheres negras/indígenas: Esses grupos aparecem apenas como figurantes ou em posições subalternas.
12. Estereótipos de papéis de gênero: Divisão rígida (mulheres apenas no lar/cuidado, homens apenas no trabalho externo).

【REGRA ESPECIAL — Corpo feminino exposto: necessário vs. desconectado do produto】
Antes de classificar o critério 1, aplique esta verificação em duas etapas. Ela vale para CORPO FEMININO \
exposto (mulheres e meninas); a presença de corpo masculino exposto, por si só, não aciona o critério 1. \
Para menores de idade (qualquer gênero), aplique a REGRA RÍGIDA PARA MENORES, descrita adiante.

PASSO A — O corpo feminino exposto é necessário para demonstrar o produto/serviço?
- Exemplos de NECESSÁRIO: anúncio de biquíni, lingerie, creme corporal, bronzeador, moda praia, \
fisioterapia, avaliação postural, produtos de skincare aplicados no corpo, aula de dança que exige \
figurino específico.
- Exemplos de DESNECESSÁRIO: anúncio de cerveja, automóvel, curso de inglês, plano de saúde, \
eletrodoméstico, banco, hamburgueria, onde o corpo aparece sem relação lógica com o que se vende.

PASSO B — Se o corpo feminino está exposto de maneira intencional E desconectado do produto/serviço, isso \
conta como DESNECESSÁRIO, independentemente de a pose ser "artística", "editorial" ou "sensual".
- Pose sensual com corpo feminino desconectado do produto → marcar critério 1 (coisificação).
- Pose artística/editorial com corpo feminino desconectado do produto → também marcar critério 1, e \
registrar "corpo desconectado do produto" na justificativa.
- Pose sensual ou artística com corpo feminino NECESSÁRIO para demonstrar o produto → NÃO marcar \
automaticamente; só marcar se houver conotação sexual explícita além do necessário.

REGRA RÍGIDA PARA MENORES (critério 2) — vale quando houver criança ou adolescente com o corpo exposto \
(roupa de banho, roupa íntima, roupas curtas ou justas, nudez parcial) ou em pose/vestuário sugestivo:
- Se o produto/serviço NÃO demandar essa exposição → classifique SEMPRE como DESNECESSÁRIO e marque o \
critério 2 (sexualização de menores), SEM exceção: pose "artística", "editorial", "inocente" ou "de \
brincadeira" não afasta a marcação. Registre "exposição de menor desconectada do produto" na justificativa.
- Se o produto/serviço demandar a exposição (ex.: moda praia infantil, roupa de banho, uniforme esportivo) → \
não marque apenas pela exposição; marque o critério 2 se a pose, o enquadramento ou o vestuário forem \
sugestivos além do que o produto exige.
- Na dúvida entre "necessário" e "desnecessário" envolvendo menores, classifique como "suspeito" e explique \
a dúvida na justificativa.

【Instruções de saída】
Retorne APENAS um JSON válido, neste formato:
{{
  "pessoas_presentes": true/false,
  "quantidade_pessoas": número,
  "pessoas": [
    {{"idade_aparente": "...", "genero_aparente": "..."}}
  ],
  "corpo_feminino_exposto": true/false,
  "menores_com_exposicao": true/false,
  "corpo_necessario_para_produto": true/false/"não aplicável",
  "resultado": "suspeito" ou "não suspeito" ou "não aplicável",
  "criterios_acionados": ["nome do critério 1", "nome do critério 2"],
  "justificativa": "Breve explicação baseada no conteúdo visual, nas pessoas identificadas e na relação entre corpo exposto e produto"
}}"""

NOMES_CRITERIOS = [
    "Coisificação", "Sexualização de menores", "Estereótipo emocional",
    "Falta de vontade própria", "Padrões de beleza inalcançáveis",
    "Padrões de beleza únicos", "Violência", "Inferioridade/dependência",
    "Linguagem discriminatória", "Ignorar diversidade",
    "Desvalorizar mulheres negras/indígenas", "Estereótipos de papéis de gênero",
]


# --------------------------------------------------------------------------
# Avisos de limitação (anexados pelo código, não pelo modelo)
# --------------------------------------------------------------------------
AVISOS_GERAIS = [
    "Triagem automatizada: o resultado é um indicativo e NÃO substitui a análise e a decisão de um revisor humano.",
    "Idade, gênero e demais características das pessoas são apenas APARENTES, inferidas visualmente, e podem estar incorretas.",
]
AVISO_CONTEXTUAIS = (
    "Critérios que dependem de contexto (falta de vontade própria, inferioridade/dependência, ignorar diversidade, "
    "desvalorizar mulheres negras/indígenas, estereótipos de papéis de gênero) são mais subjetivos e têm menos "
    "informação disponível em uma peça isolada; confirme com o contexto completo da campanha."
)
AVISO_IMAGEM = "Peça analisada como imagem estática: não há como avaliar narrativa, movimento ou falas."
AVISO_VIDEO = (
    "Vídeo analisado por amostragem de {n} quadros: cenas fora da amostra podem não ter sido avaliadas. "
    "O áudio, as falas e a narração NÃO foram analisados, então o critério 9 (linguagem discriminatória) só "
    "considera textos visíveis nos quadros."
)
AVISO_DESCRICAO_EXTERNA = (
    "A análise usou uma descrição visual fornecida externamente; sua qualidade depende dessa descrição."
)
AVISO_CORPO = (
    "Corpo feminino exposto identificado: a decisão sobre ele ser necessário ou desconectado do produto depende "
    "da identificação correta do que está sendo vendido e envolve julgamento subjetivo; confira a justificativa "
    "e a relação entre o corpo exibido e o produto."
)
AVISO_MENORES = (
    "Menores de idade com exposição identificados: foi aplicada a regra rígida (exposição não demandada pelo "
    "produto é sempre classificada como desnecessária). A idade é apenas aparente; recomenda-se revisão humana "
    "prioritária deste caso."
)
PALAVRAS_CONTEXTUAIS = (
    "vontade", "inferioridade", "dependência", "diversidade",
    "negra", "indígena", "papéis", "papeis",
)


def anexar_avisos(r: dict, tipo: str, n_quadros: int, descricao_externa: bool,
                  nota_extra: str | None = None) -> dict:
    """Anexa ao resultado as limitações da análise, para o usuário final."""
    avisos = list(AVISOS_GERAIS)
    if nota_extra:
        avisos.append(nota_extra)
    if tipo == "video":
        avisos.append(AVISO_VIDEO.format(n=n_quadros))
    elif tipo == "imagem":
        avisos.append(AVISO_IMAGEM)
    acionados = " ".join(r.get("criterios_acionados", [])).lower()
    if any(p in acionados for p in PALAVRAS_CONTEXTUAIS):
        avisos.append(AVISO_CONTEXTUAIS)
    if descricao_externa:
        avisos.append(AVISO_DESCRICAO_EXTERNA)
    if r.get("corpo_feminino_exposto"):
        avisos.append(AVISO_CORPO)
    if r.get("menores_com_exposicao"):
        avisos.append(AVISO_MENORES)
    # texto corrido: um único parágrafo, pronto para exibir ao usuário
    r["avisos_e_limitacoes"] = "Limitações desta análise: " + " ".join(avisos)
    r["site_opens"] = SITE_OPENS  # sempre no final do resultado, inclusive nos erros
    return r


# --------------------------------------------------------------------------
# Mídia -> blocos de imagem
# --------------------------------------------------------------------------
def _bloco_imagem(dados: bytes, mime: str) -> dict:
    return {
        "type": "image",
        "source": {"type": "base64", "media_type": mime,
                   "data": base64.standard_b64encode(dados).decode()},
    }


LIMITE_IMG_BYTES = 3_500_000   # folga sob o limite de ~5 MB por imagem da API
LADO_MAX_IMG = 1568            # lado maior; acima disso a API só reduz por conta própria
_HEIC_PRONTO = False


def _habilitar_heic() -> None:
    """Registra o leitor de HEIC/HEIF (fotos de iPhone), se o pacote pillow-heif estiver instalado."""
    global _HEIC_PRONTO
    if _HEIC_PRONTO:
        return
    try:
        import pillow_heif
        pillow_heif.register_heif_opener()
    except ImportError:
        pass
    _HEIC_PRONTO = True


def carregar_imagem(caminho: Path) -> list[dict]:
    """Abre a imagem em qualquer formato aceito (JPG, PNG, WebP, GIF, BMP, TIFF, HEIC, AVIF), corrige a
    rotação, achata transparência sobre fundo branco, reduz se for grande ou pesada e envia como JPEG."""
    from PIL import Image, ImageOps

    _habilitar_heic()
    try:
        with Image.open(caminho) as im:
            im.seek(0)  # GIF/TIFF/WebP animado: usa só o primeiro quadro
            im = ImageOps.exif_transpose(im)
            im.load()
            if im.mode in ("RGBA", "LA", "PA") or (im.mode == "P" and "transparency" in im.info):
                im = im.convert("RGBA")
                fundo = Image.new("RGB", im.size, (255, 255, 255))
                fundo.paste(im, mask=im.getchannel("A"))
                im = fundo
            else:
                im = im.convert("RGB")
    except Exception as e:
        ext = caminho.suffix.lower()
        dica = ""
        if ext in (".heic", ".heif", ".avif"):
            dica = " Se o problema persistir, converta a imagem para JPG ou PNG antes de enviar."
        raise ValueError(f"Não foi possível abrir a imagem ({ext}): {e}.{dica}") from e

    im.thumbnail((LADO_MAX_IMG, LADO_MAX_IMG), Image.LANCZOS)  # só reduz, nunca amplia
    for _ in range(8):
        for qualidade in (90, 80, 70):
            buf = io.BytesIO()
            im.save(buf, "JPEG", quality=qualidade, optimize=True)
            if buf.tell() <= LIMITE_IMG_BYTES:
                return [_bloco_imagem(buf.getvalue(), "image/jpeg")]
        w, h = im.size  # ainda pesada: reduz 20% e tenta de novo
        im = im.resize((max(1, int(w * 0.8)), max(1, int(h * 0.8))), Image.LANCZOS)
    raise ValueError("Não foi possível reduzir a imagem ao tamanho aceito.")


def extrair_quadros(caminho: Path, n_quadros: int, lado_max: int = 1024) -> list[dict]:
    """Amostra n quadros igualmente espaçados do vídeo."""
    import cv2

    cap = cv2.VideoCapture(str(caminho))
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    if total <= 0:
        raise RuntimeError(f"Não foi possível ler o vídeo: {caminho}")
    n = min(n_quadros, total)
    indices = sorted({int(total * (i + 0.5) / n) for i in range(n)})
    blocos = []
    for idx in indices:
        cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
        ok, quadro = cap.read()
        if not ok:
            continue
        h, w = quadro.shape[:2]
        escala = lado_max / max(h, w)
        if escala < 1:
            quadro = cv2.resize(quadro, (int(w * escala), int(h * escala)))
        ok, buf = cv2.imencode(".jpg", quadro, [cv2.IMWRITE_JPEG_QUALITY, 85])
        if ok:
            blocos.append(_bloco_imagem(buf.tobytes(), "image/jpeg"))
    cap.release()
    if not blocos:
        raise RuntimeError(f"Nenhum quadro extraído de {caminho}")
    return blocos


# --------------------------------------------------------------------------
# Etapas
# --------------------------------------------------------------------------
def _texto(resp) -> str:
    """Junta só os blocos de texto da resposta (ignora blocos de raciocínio e outros tipos)."""
    texto = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text").strip()
    if not texto:
        raise ValueError("O modelo não devolveu texto (resposta vazia ou interrompida).")
    return texto


def etapa1_descrever(client, modelo: str, blocos: list[dict]) -> str:
    resp = client.messages.create(
        model=modelo, max_tokens=4000,
        messages=[{"role": "user", "content": blocos + [{"type": "text", "text": PROMPT_DESCRICAO}]}],
    )
    return _texto(resp)


def _extrair_json(texto: str) -> dict:
    texto = re.sub(r"^```(?:json)?|```$", "", texto.strip(), flags=re.MULTILINE).strip()
    inicio, fim = texto.find("{"), texto.rfind("}")
    if inicio == -1 or fim == -1:
        raise ValueError("Resposta sem JSON.")
    return json.loads(texto[inicio:fim + 1])


def contem_menores_critério2(r: dict) -> bool:
    return any("menores" in str(c).lower() for c in r.get("criterios_acionados", []))


def _validar(r: dict) -> dict:
    """Garante o esquema e coerência mínima da saída."""
    r.setdefault("pessoas", [])
    r["pessoas_presentes"] = bool(r.get("pessoas_presentes"))
    r["quantidade_pessoas"] = int(r.get("quantidade_pessoas") or len(r["pessoas"]))
    r.setdefault("criterios_acionados", [])
    r["corpo_feminino_exposto"] = r.get("corpo_feminino_exposto") is True
    r["menores_com_exposicao"] = r.get("menores_com_exposicao") is True
    nec = r.get("corpo_necessario_para_produto")
    if not (r["corpo_feminino_exposto"] or r["menores_com_exposicao"]) or nec not in (True, False):
        nec = "não aplicável"  # sem corpo feminino/menor exposto (ou valor inválido) não há o que avaliar
    r["corpo_necessario_para_produto"] = nec
    # campos de versões anteriores do prompt
    r.pop("pose_artistica_identificada", None)
    r.pop("corpo_exposto", None)
    # regra rígida: menor com exposição desnecessária => critério 2 sempre marcado
    if r["menores_com_exposicao"] and nec is False and not contem_menores_critério2(r):
        r["criterios_acionados"] = list(r["criterios_acionados"]) + ["Sexualização de menores"]
    r.setdefault("justificativa", "")
    if r.get("resultado") not in {"suspeito", "não suspeito", "não aplicável"}:
        r["resultado"] = "suspeito" if r["criterios_acionados"] else "não suspeito"
    # critérios acionados => suspeito; sem pessoas e sem critérios => não aplicável
    if r["criterios_acionados"]:
        r["resultado"] = "suspeito"
    elif not r["pessoas_presentes"]:
        r["resultado"] = "não aplicável"
    return r


def etapa2_auditar(client, modelo: str, descricao: str) -> dict:
    prompt = PROMPT_AUDITORIA.format(descricao=descricao)
    ultimo_erro = None
    for _ in range(2):  # 1 retentativa se o JSON vier inválido
        resp = client.messages.create(
            model=modelo, max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
        try:
            return _validar(_extrair_json(_texto(resp)))
        except (ValueError, json.JSONDecodeError) as e:
            ultimo_erro = e
    raise RuntimeError(f"Não foi possível obter JSON válido: {ultimo_erro}")


def analisar(caminho: Path, client, modelo: str, n_quadros: int,
             descricao_externa: str | None = None, nota_extra: str | None = None) -> dict:
    ext = caminho.suffix.lower()
    if ext in EXT_IMAGEM:
        tipo = "imagem"
    elif ext in EXT_VIDEO:
        tipo = "video"
    else:
        raise ValueError(f"Formato não suportado: {ext}")

    if descricao_externa:
        descricao = descricao_externa
    elif tipo == "imagem":
        descricao = etapa1_descrever(client, modelo, carregar_imagem(caminho))
    else:
        descricao = etapa1_descrever(client, modelo, extrair_quadros(caminho, n_quadros))

    resultado = etapa2_auditar(client, modelo, descricao)
    resultado["arquivo"] = caminho.name
    return anexar_avisos(resultado, tipo, n_quadros, bool(descricao_externa), nota_extra)


# --------------------------------------------------------------------------
# Base de dados: coleta e armazenamento de imagens, vídeos e links
# --------------------------------------------------------------------------
PASTA_BASE_PADRAO = Path("base_opens")  # pasta das mídias (os metadados ficam no PostgreSQL)
LIMITE_DOWNLOAD = 100 * 1024 * 1024  # 100 MB por arquivo baixado
TERMO_VERSAO = "1.0"
RETENCAO_PADRAO_DIAS = 180


def aviso_privacidade(dias: int) -> str:
    contato = os.environ.get("OPENS_CONTATO_PRIVACIDADE", "[defina OPENS_CONTATO_PRIVACIDADE]")
    return (
        f"AVISO DE PRIVACIDADE (LGPD) — versão {TERMO_VERSAO}\n"
        "Finalidade: auditar peças publicitárias segundo os critérios do OPeNS e compor uma base de pesquisa.\n"
        "Dados tratados: imagem/vídeo ou link enviado, resultado da análise e um identificador pseudonimizado "
        "de quem enviou.\n"
        "Compartilhamento: o conteúdo é processado pela API da Anthropic (operador) para gerar a análise.\n"
        "Menores de idade: mídias com pessoas aparentemente menores não são armazenadas, apenas a análise.\n"
        f"Retenção: {dias} dias; depois os dados e as mídias são excluídos automaticamente.\n"
        "Seus direitos: acesso, correção e exclusão a qualquer momento, pelo contato "
        f"{contato}.\n"
        "Envie apenas material que você tem direito de compartilhar; evite imagens de pessoas privadas."
    )
TIPOS_MIME = {
    "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif",
    "image/bmp": ".bmp", "image/x-ms-bmp": ".bmp", "image/tiff": ".tiff",
    "image/heic": ".heic", "image/heif": ".heif", "image/avif": ".avif",
    "video/mp4": ".mp4", "video/quicktime": ".mov", "video/webm": ".webm",
    "video/x-matroska": ".mkv", "video/x-msvideo": ".avi",
}


class LinkSemMidia(Exception):
    """O link não aponta diretamente para uma imagem ou vídeo."""


def conectar_base(pasta: Path) -> psycopg.Connection:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("Defina DATABASE_URL (ex.: postgresql://usuario:senha@host:5432/opens).")
    (pasta / "midias").mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(pasta / "midias", 0o700)  # só o dono da aplicação acessa as mídias
    except OSError:
        pass
    con = psycopg.connect(url)
    con.execute("""
        CREATE TABLE IF NOT EXISTS submissoes (
            id                   BIGSERIAL PRIMARY KEY,
            data_hora            TIMESTAMPTZ NOT NULL DEFAULT now(),
            retencao_ate         TIMESTAMPTZ NOT NULL,
            usuario_hash         TEXT,                 -- HMAC do identificador (pseudonimização)
            origem               TEXT NOT NULL,        -- 'arquivo' ou 'link'
            link                 TEXT,                 -- sem query string nem credenciais
            tipo                 TEXT,                 -- 'imagem' ou 'video'
            sha256               TEXT,
            caminho_midia        TEXT,
            midia_retida         BOOLEAN NOT NULL DEFAULT FALSE,
            contem_menores       BOOLEAN NOT NULL DEFAULT FALSE,
            consentimento_versao TEXT NOT NULL,
            consentimento_em     TIMESTAMPTZ NOT NULL,
            resultado            TEXT,
            criterios            TEXT[],
            analise              JSONB,
            erro                 TEXT
        )""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_sub_retencao ON submissoes (retencao_ate)")
    con.execute("CREATE INDEX IF NOT EXISTS ix_sub_usuario ON submissoes (usuario_hash)")
    con.execute("CREATE INDEX IF NOT EXISTS ix_sub_sha ON submissoes (sha256)")
    con.commit()
    return con


def pseudonimizar(usuario: str | None) -> str | None:
    """Troca o identificador por um HMAC; sem o segredo (OPENS_SALT) não dá para reverter."""
    if not usuario:
        return None
    sal = os.environ.get("OPENS_SALT")
    if not sal:
        raise RuntimeError("Defina OPENS_SALT (segredo longo e aleatório) para pseudonimizar o usuário.")
    return hmac.new(sal.encode(), usuario.strip().lower().encode(), hashlib.sha256).hexdigest()


def limpar_link(url: str) -> str:
    """Remove credenciais, query string e fragmento antes de gravar o link."""
    p = urllib.parse.urlparse(url)
    host = p.hostname or ""
    if p.port:
        host += f":{p.port}"
    return f"{p.scheme}://{host}{p.path}"


def contem_menores(r: dict) -> bool:
    """Há pessoa aparentemente menor de idade, ou o critério 2 foi acionado."""
    idades = {"criança", "crianca", "adolescente"}
    if any(str(p.get("idade_aparente", "")).lower() in idades for p in r.get("pessoas", [])):
        return True
    return any("menores" in c.lower() for c in r.get("criterios_acionados", []))


def _validar_url(url: str) -> None:
    """Aceita só http/https e bloqueia endereços internos (evita SSRF)."""
    partes = urllib.parse.urlparse(url)
    if partes.scheme not in ("http", "https") or not partes.hostname:
        raise ValueError("Link inválido: use um endereço http:// ou https://")
    try:
        enderecos = {ai[4][0] for ai in socket.getaddrinfo(partes.hostname, None)}
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver o endereço do link: {e}")
    for ip in enderecos:
        if not ipaddress.ip_address(ip.split("%")[0]).is_global:
            raise ValueError("Link bloqueado: aponta para um endereço interno/privado.")


class _Redirecionador(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validar_url(newurl)  # revalida a cada redirecionamento
        return super().redirect_request(req, fp, code, msg, headers, newurl)


HTML_MIMES = ("text/html", "application/xhtml+xml")
LIMITE_PAGINA = 2 * 1024 * 1024  # 2 MB de HTML é mais que suficiente para ler as meta tags
NOTA_LINK_PAGINA = (
    "Link de página da web: como o endereço não aponta direto para um arquivo, foi analisada a mídia de "
    "pré-visualização declarada pela página (imagem ou vídeo principal), e não a página inteira. Páginas "
    "que exigem login ou carregam o conteúdo por script podem fornecer uma imagem genérica; nesses casos, "
    "use o endereço direto da imagem ou envie o arquivo."
)
MENSAGEM_LINK_SEM_MIDIA = (
    "O link é uma página da web e não foi possível encontrar nela uma imagem ou vídeo para análise. "
    "Use o endereço direto da imagem (clique com o botão direito na imagem e escolha \"Copiar endereço "
    "da imagem\") ou envie o arquivo."
)


def _midias_da_pagina(texto: str, url_base: str) -> list[str]:
    """Mídias que a própria página declara como principais (og:video, og:image, twitter:image)."""
    videos, imagens = [], []
    for tag in re.findall(r"<meta\b[^>]*>", texto, flags=re.I):
        chave = re.search(r'(?:property|name)\s*=\s*["\']([^"\']+)["\']', tag, flags=re.I)
        valor = re.search(r'content\s*=\s*["\']([^"\']+)["\']', tag, flags=re.I)
        if not chave or not valor:
            continue
        alvo = urllib.parse.urljoin(url_base, html.unescape(valor.group(1).strip()))
        k = chave.group(1).lower()
        if k in ("og:video", "og:video:url", "og:video:secure_url", "twitter:player:stream"):
            videos.append(alvo)
        elif k in ("og:image", "og:image:url", "og:image:secure_url", "twitter:image", "twitter:image:src"):
            imagens.append(alvo)
    return list(dict.fromkeys(videos + imagens))  # vídeos primeiro; sem repetidos


def baixar_link(url: str, pasta_tmp: Path, _nivel: int = 0) -> tuple[Path, str | None]:
    """Baixa imagem/vídeo de um link para uma pasta temporária.

    Aceita link direto de arquivo. Se o link for uma página da web, usa a mídia principal que a
    página declara (og:video / og:image). Devolve (caminho, nota); a nota só existe no caso da página.
    """
    _validar_url(url)
    opener = urllib.request.build_opener(_Redirecionador)
    req = urllib.request.Request(url, headers={"User-Agent": "OPeNS-Auditor/1.0"})
    pagina = None
    with opener.open(req, timeout=30) as resp:
        mime = resp.headers.get_content_type()
        if mime in HTML_MIMES:
            charset = resp.headers.get_content_charset() or "utf-8"
            pagina = resp.read(LIMITE_PAGINA).decode(charset, errors="replace")
            url_final = resp.geturl()
        else:
            ext = TIPOS_MIME.get(mime)
            if ext is None:
                ext_url = Path(urllib.parse.urlparse(url).path).suffix.lower()
                if mime in ("application/octet-stream", "binary/octet-stream") \
                        and ext_url in EXT_IMAGEM | EXT_VIDEO:
                    ext = ext_url
                else:
                    raise LinkSemMidia(f"O link não aponta para uma imagem ou vídeo (tipo: {mime}).")
            destino = pasta_tmp / f"download_{hashlib.sha1(url.encode()).hexdigest()[:10]}{ext}"
            total = 0
            with open(destino, "wb") as f:
                while chunk := resp.read(1024 * 1024):
                    total += len(chunk)
                    if total > LIMITE_DOWNLOAD:
                        raise ValueError("Arquivo do link excede o limite de 100 MB.")
                    f.write(chunk)
            return destino, None

    # Link de página: tenta as mídias declaradas por ela (só um nível, para não entrar em laço)
    if _nivel == 0:
        for candidata in _midias_da_pagina(pagina, url_final)[:5]:
            try:
                caminho, _ = baixar_link(candidata, pasta_tmp, _nivel=1)
                return caminho, NOTA_LINK_PAGINA
            except (LinkSemMidia, ValueError, OSError):
                continue  # candidata inválida, bloqueada ou fora do ar: tenta a próxima
    raise LinkSemMidia(MENSAGEM_LINK_SEM_MIDIA)


def guardar_midia(pasta: Path, caminho: Path) -> tuple[str, Path]:
    """Copia a mídia para a base usando o SHA-256 como nome (sem duplicar)."""
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    sha = h.hexdigest()
    destino = pasta / "midias" / f"{sha}{caminho.suffix.lower()}"
    if not destino.exists():
        shutil.copy2(caminho, destino)
    return sha, destino


def registrar(con: psycopg.Connection, pasta: Path, origem: str, link: str | None,
              caminho: Path | None, r: dict, usuario_hash: str | None, dias: int) -> None:
    menores = contem_menores(r)
    sha = destino = tipo = None
    if caminho is not None and caminho.exists():
        ext = caminho.suffix.lower()
        if ext in EXT_IMAGEM | EXT_VIDEO:
            tipo = "video" if ext in EXT_VIDEO else "imagem"
            if not menores:  # minimização: mídia com menores não é retida
                sha, destino = guardar_midia(pasta, caminho)
    link_limpo = limpar_link(link) if link else None
    dados = {**r, "arquivo": link_limpo or "(arquivo enviado)"}  # sem nome de arquivo do usuário
    dados.pop("id_base", None)
    cur = con.execute(
        """INSERT INTO submissoes (retencao_ate, usuario_hash, origem, link, tipo, sha256,
                                   caminho_midia, midia_retida, contem_menores,
                                   consentimento_versao, consentimento_em,
                                   resultado, criterios, analise, erro)
           VALUES (now() + (%s * interval '1 day'), %s, %s, %s, %s, %s, %s, %s, %s,
                   %s, now(), %s, %s, %s, %s)
           RETURNING id""",
        (dias, usuario_hash, origem, link_limpo, tipo, sha,
         str(destino.resolve()) if destino else None, destino is not None, menores,
         TERMO_VERSAO, r.get("resultado"), r.get("criterios_acionados", []),
         Jsonb(dados), r.get("erro")),
    )
    r["id_base"] = cur.fetchone()[0]
    con.commit()


def _remover_midias_orfas(con: psycopg.Connection, removidos: list) -> None:
    """Apaga do disco as mídias que nenhum registro restante usa mais."""
    for sha, caminho in removidos:
        if sha and caminho and not con.execute(
                "SELECT 1 FROM submissoes WHERE sha256 = %s LIMIT 1", (sha,)).fetchone():
            Path(caminho).unlink(missing_ok=True)


def purgar(con: psycopg.Connection) -> int:
    """Exclui registros e mídias cuja retenção expirou."""
    removidos = con.execute(
        "DELETE FROM submissoes WHERE retencao_ate < now() RETURNING sha256, caminho_midia").fetchall()
    con.commit()
    _remover_midias_orfas(con, removidos)
    return len(removidos)


def excluir(con: psycopg.Connection, ids: list[int] | None = None,
            usuario_hash: str | None = None) -> int:
    """Direito de exclusão do titular: por id de submissão ou por usuário."""
    if ids:
        removidos = con.execute(
            "DELETE FROM submissoes WHERE id = ANY(%s) RETURNING sha256, caminho_midia", (ids,)).fetchall()
    elif usuario_hash:
        removidos = con.execute(
            "DELETE FROM submissoes WHERE usuario_hash = %s RETURNING sha256, caminho_midia",
            (usuario_hash,)).fetchall()
    else:
        return 0
    con.commit()
    _remover_midias_orfas(con, removidos)
    return len(removidos)


def listar(con: psycopg.Connection, n: int = 20) -> None:
    linhas = con.execute(
        """SELECT id, to_char(data_hora, 'YYYY-MM-DD HH24:MI'), LEFT(COALESCE(usuario_hash, '-'), 8),
                  origem, COALESCE(link, '(arquivo)'), COALESCE(resultado, 'erro'),
                  retencao_ate::date
           FROM submissoes ORDER BY id DESC LIMIT %s""", (n,)).fetchall()
    print("id | data/hora | usuário(hash) | origem | link | resultado | retido até")
    for linha in linhas:
        print(" | ".join(str(c) for c in linha))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Auditor OPeNS para imagens e vídeos")
    ap.add_argument("entrada", type=Path, nargs="*", help="imagens, vídeos ou pastas")
    ap.add_argument("--link", action="append", default=[],
                    help="link direto para imagem/vídeo (repita a opção para vários)")
    ap.add_argument("--usuario", help="identificador de quem enviou o material (gravado como hash)")
    ap.add_argument("--base", type=Path, default=PASTA_BASE_PADRAO,
                    help="pasta onde as mídias são guardadas (padrão: ./base_opens)")
    ap.add_argument("--consentimento", action="store_true",
                    help="confirma que o usuário aceitou o aviso de privacidade; sem isso nada é armazenado")
    ap.add_argument("--retencao-dias", type=int, default=RETENCAO_PADRAO_DIAS,
                    help=f"dias de retenção dos dados (padrão {RETENCAO_PADRAO_DIAS})")
    ap.add_argument("--privacidade", action="store_true", help="mostra o aviso de privacidade e sai")
    ap.add_argument("--listar", action="store_true", help="lista as últimas submissões e sai")
    ap.add_argument("--purgar", action="store_true", help="exclui registros e mídias com retenção expirada")
    ap.add_argument("--excluir", type=int, action="append", default=[], metavar="ID",
                    help="exclui a submissão de id ID (repita para várias)")
    ap.add_argument("--excluir-usuario", metavar="USUARIO",
                    help="exclui todas as submissões desse usuário")
    ap.add_argument("--frames", type=int, default=8, help="quadros amostrados por vídeo (padrão 8)")
    ap.add_argument("--modelo", default=MODELO_PADRAO)
    ap.add_argument("--descricao-vlm", type=Path,
                    help="arquivo .txt com a análise visual já pronta (ex.: VLM Run); pula a etapa 1")
    ap.add_argument("--saida", type=Path, help="salvar resultados em JSON")
    args = ap.parse_args()

    if args.privacidade:
        print(aviso_privacidade(args.retencao_dias))
        return
    if args.listar or args.purgar or args.excluir or args.excluir_usuario:
        con = conectar_base(args.base)
        if args.purgar:
            print(f"{purgar(con)} registro(s) expirado(s) excluído(s).")
        if args.excluir:
            print(f"{excluir(con, ids=args.excluir)} registro(s) excluído(s) por id.")
        if args.excluir_usuario:
            print(f"{excluir(con, usuario_hash=pseudonimizar(args.excluir_usuario))} "
                  "registro(s) do usuário excluído(s).")
        if args.listar:
            listar(con)
        return
    if not args.entrada and not args.link:
        ap.error("informe ao menos um arquivo/pasta ou um --link")

    client = anthropic.Anthropic()
    descricao_externa = args.descricao_vlm.read_text(encoding="utf-8") if args.descricao_vlm else None

    # Armazenamento só com consentimento registrado
    con = usuario_hash = None
    if args.consentimento:
        usuario_hash = pseudonimizar(args.usuario)  # falha cedo se faltar OPENS_SALT
        con = conectar_base(args.base)
        print(aviso_privacidade(args.retencao_dias), file=sys.stderr)
        expurgados = purgar(con)
        if expurgados:
            print(f"[privacidade] {expurgados} registro(s) expirado(s) excluído(s).", file=sys.stderr)
    else:
        print("[privacidade] Sem --consentimento: a análise será feita, mas nada será armazenado.",
              file=sys.stderr)

    arquivos = []
    for e in args.entrada:
        if e.is_dir():
            arquivos += sorted(p for p in e.iterdir() if p.suffix.lower() in EXT_IMAGEM | EXT_VIDEO)
        else:
            arquivos.append(e)
    itens = [("arquivo", None, p) for p in arquivos] + [("link", u, None) for u in args.link]

    resultados = []
    with tempfile.TemporaryDirectory() as tmp:
        for origem, link, arq in itens:
            nota = None
            try:
                if origem == "link":
                    arq, nota = baixar_link(link, Path(tmp))
                r = analisar(arq, client, args.modelo, args.frames, descricao_externa, nota)
            except Exception as e:  # um item com erro não derruba o lote
                ext = arq.suffix.lower() if arq else ""
                tipo = "video" if ext in EXT_VIDEO else "imagem" if ext in EXT_IMAGEM else None
                r = anexar_avisos({"arquivo": link or arq.name, "erro": str(e)}, tipo,
                                  args.frames, bool(descricao_externa), nota)
            if link:
                r["arquivo"] = link
            if con is not None:
                registrar(con, args.base, origem, link, arq, r, usuario_hash, args.retencao_dias)
            resultados.append(r)
            print(json.dumps(r, ensure_ascii=False, indent=2))

    if args.saida:
        args.saida.write_text(json.dumps(resultados, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nSalvo em {args.saida}", file=sys.stderr)


if __name__ == "__main__":
    main()
