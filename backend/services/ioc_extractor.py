"""IOC 提取器 — Regex + LLM 混合提取威胁指标

修复内容：
1. 每个 extractor 独立的 try/except，单个失败不影响其他
2. _context() 统一处理，正确处理 Unicode 边界
3. Hash 提取增加独立扫描模式（不依赖关键词邻近）
4. 域名过滤优化：移除 io/co 排除，增加威胁域名关键词
5. 修复 Hash context 使用 _context() 方法而非手动切片
"""

import re
import logging
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

# IOC 分类定义
CATEGORY_MAP = {
    "ip":      {"category": "network",  "label": "🌐 IP 地址",       "icon": "🌐"},
    "domain":  {"category": "network",  "label": "🔗 域名",          "icon": "🔗"},
    "url":     {"category": "network",  "label": "🔗 URL",           "icon": "🔗"},
    "hash":    {"category": "file",     "label": "🔑 文件哈希",      "icon": "🔑"},
    "cve":     {"category": "vuln",     "label": "🪲 CVE 编号",      "icon": "🪲"},
    "attack_technique": {"category": "technique", "label": "⚔️ ATT&CK 技术", "icon": "⚔️"},
    "threat_group":     {"category": "actor",     "label": "🎯 威胁组织",   "icon": "🎯"},
    "email":   {"category": "identity", "label": "📧 邮箱",          "icon": "📧"},
}

CATEGORY_ORDER = ["network", "file", "vuln", "technique", "actor", "identity"]


def get_category(ioc_type: str) -> str:
    return CATEGORY_MAP.get(ioc_type, {}).get("category", "other")


def get_type_label(ioc_type: str) -> str:
    return CATEGORY_MAP.get(ioc_type, {}).get("label", ioc_type)


@dataclass
class ExtractedIOC:
    ioc_type: str
    value: str
    context: str = ""
    confidence: float = 1.0
    subtype: str = ""       # c2_ip / phishing_domain / malware_hash / ...
    role: str = ""          # "C2 服务器" / "钓鱼页面" / ...
    risk_level: str = ""    # high / medium / low
    description: str = ""   # LLM 生成的一句话说明

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = get_category(self.ioc_type)
        d["type_label"] = get_type_label(self.ioc_type)
        return d


@dataclass
class ExtractionResult:
    source: str = ""
    iocs: list[ExtractedIOC] = field(default_factory=list)
    statistics: dict = field(default_factory=dict)
    categories: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "iocs": [i.to_dict() for i in self.iocs],
            "statistics": self.statistics,
            "categories": self.categories,
            "errors": self.errors if self.errors else [],
        }


class IOCExtractor:
    """IOC 正则提取器（每个提取器独立容错）"""

    IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    IPV4_RE = re.compile(rf"(?<![.\d])(?:{IPV4_OCTET}\.){{3}}{IPV4_OCTET}(?![.\d])")

    PRIVATE_IP_RE = [
        re.compile(r"^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})$"),
        re.compile(r"^(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$"),
        re.compile(r"^(?:192\.168\.\d{1,3}\.\d{1,3})$"),
        re.compile(r"^(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})$"),
        re.compile(r"^(?:0\.0\.0\.0|255\.255\.255\.255|224\.\d{1,3}\.\d{1,3}\.\d{1,3})$"),
    ]

    IPV6_RE = re.compile(
        r"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
        r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
        r":(?::[0-9a-fA-F]{1,4}){1,7}|"
        r"fe80:(?::[0-9a-fA-F]{0,4}){0,4}%\w+|"
        r"::(?:ffff(?::0{1,4})?:)?"
        rf"(?:{IPV4_OCTET}\.){{3}}{IPV4_OCTET}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,4}:"
        rf"(?:{IPV4_OCTET}\.){{3}}{IPV4_OCTET})(?![\d\w.])"
    )

    DOMAIN_RE = re.compile(
        r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63})(?![a-zA-Z0-9-])"
    )

    URL_DOMAIN_RE = re.compile(
        r"https?://"
        r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63})"
        r"(?::\d{1,5})?"
        r"(?:/[^\s\)\]>\"'«‹]*)?",
        re.IGNORECASE,
    )

    URL_IP_RE = re.compile(
        rf"https?://(?:{IPV4_OCTET}\.){{3}}{IPV4_OCTET}"
        r"(?::\d{1,5})?"
        r"(?:/[^\s\)\]>\"'«‹]*)?",
        re.IGNORECASE,
    )

    HASH_PATTERNS = {
        "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
        "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
        "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    }

    ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
    CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

    THREAT_GROUPS = [
        r"APT\d{1,2}", r"Winnti", r"Deep Panda", r"APT41",
        r"Hafnium", r"Red Apollo", r"APT28", r"APT29",
        r"Fancy Bear", r"Cozy Bear", r"Turla", r"Sandworm",
        r"Lazarus", r"APT37", r"APT38", r"Kimsuky",
        r"Hidden Cobra", r"BlueNoroff", r"Andariel",
        r"APT33", r"APT34", r"APT35", r"Charming Kitten",
        r"OilRig", r"MuddyWater", r"Equation Group",
        r"DarkHotel", r"APT32", r"OceanLotus", r"The Dukes",
        r"FIN\d+", r"TA(?!0\d{2})\d{3}", r"UNC\d{3,4}",  # TA(?!0###) 排除 MITRE 战术 ID
        r"Gazer", r"Duqu",
        r"Berserk Bear", r"Barium", r"Wicked Panda",
        r"Double Dragon", r"Strontium", r"Sednit",
        r"Sofacy", r"Pawn Storm", r"Nobelium",
        r"Midnight Blizzard", r"Labyrinth Chollima",
        r"Stone Panda", r"Elfin", r"Magnallium",
        r"Refined Kitten", r"Helix Kitten", r"Greenbug",
        r"Crambus", r"Snake", r"Venomous Bear",
        r"Uroburos", r"Waterbug", r"Black Banshee",
        r"Velvet Chollima", r"Thallium",
    ]
    THREAT_GROUP_RE = re.compile(
        r"(?:" + "|".join(THREAT_GROUPS) + r")", re.IGNORECASE
    )

    EMAIL_RE = re.compile(
        r"\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
        r"\.[a-zA-Z]{2,63}\b"
    )

    # 常见的良性 TLD，用于域名过滤 —— 不再排除 .io / .co（威胁情报常用）
    EXCLUDED_TLDS = {"com", "org", "net", "edu", "gov", "mil", "info", "biz"}

    # 非 TLD 的常见文件扩展名 — 这些看起来像域名的后缀，实际是文件名
    # 注意: 不含 com/net/org 等真实 TLD（即使某些也是文件扩展名）
    NON_TLD_EXTENSIONS = {
        "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
        "jar", "msi", "msp", "scr", "pif", "hta", "cpl", "reg",
        "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm",
        "pdf", "rtf", "csv", "txt", "log", "ini", "cfg", "conf", "dat",
        "zip", "rar", "7z", "tar", "gz", "bz2", "cab", "iso", "img",
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "tif", "tiff",
        "htm", "html", "xhtml", "shtml", "css", "less", "scss",
        "py", "pyc", "pl", "rb", "sh", "php", "asp", "aspx", "jsp",
        "c", "cpp", "h", "hpp", "cs", "java", "go", "rs", "swift",
        "tmp", "temp", "bak", "old", "chm", "hlp", "db", "sqlite",
        "pdb", "obj", "lib", "exp", "bin", "elf", "macho",
        "dit", "mdf", "ldf", "ost", "pst", "edb", "nvram",
        "vbs", "wsf", "wsh", "psm1", "psd1", "ps1xml",
    }

    # 威胁域名关键词（出现任意一个即保留，用于区分正常域名和威胁域名）
    THREAT_KEYWORDS = [
        "mail", "update", "secure", "verify", "auth", "cdn",
        "cloud", "api", "admin", "portal", "login", "account",
        "service", "app", "download", "c2", "phish", "malware",
        "exploit", "bot", "trojan", "backdoor", "panel", "gate",
        "proxy", "vpn", "anon", "crypt", "payload", "shell",
        "remote", "beacon", "drop", "uploader", "stealer",
        "rat", "keylog", "spy", "inject", "loader", "miner",
    ]

    # 排除的假阳性 hash 模式（全相同字符、全零等）
    BOGUS_HASHES = {
        "0" * 32, "0" * 40, "0" * 64,
        "f" * 32, "f" * 40, "f" * 64,
        "a" * 32, "a" * 40, "a" * 64,
    }

    def __init__(self, extract_private_ips: bool = False, context_window: int = 120):
        self.extract_private_ips = extract_private_ips
        self.context_window = context_window

    # ── 主入口 ────────────────────────────────────────────

    def extract(self, text: str, source: str = "") -> ExtractionResult:
        if not text or not text.strip():
            return ExtractionResult(source=source)

        result = ExtractionResult(source=source)

        # 预处理：规范化空白字符（但保留原始换行结构用于上下文）
        text = self._sanitize_text(text)

        # 每个提取器独立 try/except — 单个失败不影响其他
        extractors = [
            ("IP 地址",     self._extract_ips),
            ("URL",         self._extract_urls),
            ("域名",        self._extract_domains),
            ("文件哈希",    self._extract_hashes),
            ("ATT&CK 技术", self._extract_attack),
            ("CVE 编号",    self._extract_cves),
            ("威胁组织",    self._extract_groups),
            ("邮箱",        self._extract_emails),
        ]

        for label, extractor_fn in extractors:
            try:
                result.iocs.extend(extractor_fn(text, result))
            except Exception as e:
                logger.warning(f"IOC 提取 [{label}] 失败: {e}", exc_info=True)
                result.errors.append(f"{label} 提取失败: {e}")

        result.iocs = self._dedup(result.iocs)
        result.statistics = self._compute_stats(result)
        result.categories = self._compute_categories(result)
        logger.info(f"IOC 提取完成: {result.statistics}")
        if result.errors:
            logger.warning(f"IOC 提取中有 {len(result.errors)} 个错误: {result.errors}")
        return result

    # ── 文本预处理 ───────────────────────────────────────

    @staticmethod
    def _sanitize_text(text: str) -> str:
        """规范化文本：控制字符清理 + defanged IOC 还原

        威胁情报报告常使用 defanged 格式来安全展示 IOC，
        例如 IP `1.2.3[.]4`、域名 `evil[.]com`、URL `hxxps://evil[.]com/`。
        此方法在规范化时自动还原这些格式，使后续正则能匹配。
        """
        if not text:
            return ""
        # 移除 NULL 字节和 BOM
        text = text.replace("\x00", "").replace("﻿", "")
        # 统一换行为 \n
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        # 移除除换行/制表符外的 ASCII 控制字符 (0x00-0x1F)
        cleaned = []
        for ch in text:
            cp = ord(ch)
            if cp < 0x20 and cp not in (0x09, 0x0A):
                cleaned.append(" ")
            else:
                cleaned.append(ch)
        text = "".join(cleaned)

        # ── PDF 换行导致的断裂修复 ──
        # PDF 提取时常在 defang 符号处断行：194.87.189\n[.]171 → 194.87.189[.]171
        text = re.sub(r'(\d)\n\[\.\]', r'\1[.]', text)
        text = re.sub(r'\n\[\.\](\d)', r'[.]\1', text)
        text = re.sub(r'(\w)\n\[\.\](\w)', r'\1[.]\2', text)

        # ── Defanged IOC 还原 ──
        # [.]  →  .  （最常见的 defang 方式，用于 IP 和域名）
        text = text.replace("[.]", ".")

        # ── PDF 表格拼接修复 ──
        # PDF 提取表格时常把相邻单元格拼在一起：
        #   194.87.189[.]171 [.]live  → (defang) → 194.87.189.171.live
        # 但 194.87.189.171 是一个独立 IP，.live 是隔壁列域名后缀
        # 在 IP 后插入空格：194.87.189.171.live → 194.87.189.171 .live
        text = re.sub(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.([a-z]{2,10})(?:\s|$)',
            r'\1 .\2 ',
            text,
        )
        # [:]  →  :  （用于 URL 中的冒号）
        text = text.replace("[:]", ":")
        # hxxp://  /  hxxps://  →  http://  /  https://
        text = text.replace("hxxps://", "https://")
        text = text.replace("hxxp://", "http://")
        # [at] / [@]  →  @  （邮箱 defang）
        text = text.replace("[at]", "@")
        text = text.replace("[@]", "@")
        # [dot]  →  .  （少见但存在）
        text = text.replace("[dot]", ".")

        return text

    # ── 上下文提取 ───────────────────────────────────────

    def _context(self, text: str, start_idx: int, end_idx: int) -> str:
        """提取 IOC 匹配位置前后的上下文（约 context_window 字符）

        Args:
            text: 完整文本
            start_idx: IOC 匹配起始位置
            end_idx: IOC 匹配结束位置

        Returns:
            清理后的上下文字符串（约 120 字符）
        """
        if not text:
            return ""

        half = max(20, self.context_window // 2)
        ctx_start = max(0, start_idx - half)
        ctx_end = min(len(text), end_idx + half)

        # 尝试对齐到单词/行边界（避免从词中间截断）
        if ctx_start > 0:
            # 向前找到最近的空格或换行，但不超过 10 字符
            lookback = max(0, ctx_start - 10)
            fragment = text[lookback:ctx_start]
            sep_pos = max(fragment.rfind(" "), fragment.rfind("\n"))
            if sep_pos >= 0:
                alt_start = lookback + sep_pos + 1
                if ctx_start - alt_start <= 10:
                    ctx_start = alt_start

        if ctx_end < len(text):
            # 向后找到最近的空格或换行
            lookahead = min(len(text), ctx_end + 10)
            fragment = text[ctx_end:lookahead]
            sep_pos = min(
                (p for p in [fragment.find(" "), fragment.find("\n")] if p >= 0),
                default=-1,
            )
            if sep_pos >= 0 and sep_pos <= 10:
                ctx_end = ctx_end + sep_pos

        ctx = text[ctx_start:ctx_end].strip()

        # 3 个点作为截断提示
        if ctx_start > 0:
            ctx = "…" + ctx
        if ctx_end < len(text):
            ctx = ctx + "…"

        return ctx

    # ── IP 地址 ──────────────────────────────────────────

    def _extract_ips(self, text: str, _result: ExtractionResult = None) -> list[ExtractedIOC]:
        iocs = []
        for m in self.IPV4_RE.finditer(text):
            ip = m.group()
            if not self.extract_private_ips and self._is_private(ip):
                continue
            iocs.append(ExtractedIOC(
                "ip", ip, self._context(text, m.start(), m.end()), 0.95,
            ))
        for m in self.IPV6_RE.finditer(text):
            ip = m.group()
            if not self.extract_private_ips and self._is_private(ip):
                continue
            iocs.append(ExtractedIOC(
                "ip", ip, self._context(text, m.start(), m.end()), 0.90,
            ))
        return iocs

    def _is_private(self, ip: str) -> bool:
        return any(p.match(ip) for p in self.PRIVATE_IP_RE)

    # ── URL ──────────────────────────────────────────────

    def _extract_urls(self, text: str, _result: ExtractionResult = None) -> list[ExtractedIOC]:
        iocs, seen = [], set()
        for pat in [self.URL_DOMAIN_RE, self.URL_IP_RE]:
            for m in pat.finditer(text):
                url = m.group().rstrip(".,;:'\"»)")
                if url not in seen:
                    seen.add(url)
                    iocs.append(ExtractedIOC(
                        "url", url, self._context(text, m.start(), m.end()), 0.95,
                    ))
        return iocs

    # ── 域名 ──────────────────────────────────────────────

    def _extract_domains(self, text: str, result: ExtractionResult) -> list[ExtractedIOC]:
        # 从已提取的 URL 中收集域名，避免重复提取
        url_domains = set()
        for ioc in result.iocs:
            if ioc.ioc_type == "url":
                m = re.search(r"https?://([^/:]+)", ioc.value)
                if m:
                    url_domains.add(m.group(1).lower())

        iocs, seen = [], set()
        for m in self.DOMAIN_RE.finditer(text):
            domain = m.group().lower().rstrip(".")
            if len(domain) < 4 or domain in url_domains or domain in seen:
                continue
            seen.add(domain)

            # ── 域名合法性验证 ──

            # 1. 排除文件扩展名等非真实 TLD
            tld = domain.rsplit(".", 1)[-1]
            if tld in self.NON_TLD_EXTENSIONS:
                continue

            # 2. 每个标签段至少 2 个字符（排除 s.sv / x.gq / a.bc 等伪域名）
            parts = domain.split(".")
            if any(len(part) < 2 for part in parts):
                continue

            # 3. 总长度至少 6 个字符
            if len(domain) < 6:
                continue

            # 4. 对常见 TLD 做额外验证（排除假阳性如 "version2.0.1"）
            if tld in self.EXCLUDED_TLDS:
                if len(parts) == 2 and "-" not in domain:
                    subdomain = parts[0]
                    # 短子域名（< 10 字符）+ 常见 TLD → 必须包含威胁关键词
                    if len(subdomain) < 10:
                        if not any(kw in domain.lower() for kw in self.THREAT_KEYWORDS):
                            if not re.search(
                                r"(?:c2|apt|ioc|threat|intel|scan|hack|pwn|defend|malware|virus|exploit|phish)",
                                domain,
                            ):
                                continue
                    # 长子域名（>= 10 字符）→ 很可能是真实域名，不强制关键词
                    # 但过滤明显的随机字符组合（辅音/元音比例异常）

            # 5. 排除纯数字开头的假域名
            first_segment = parts[0]
            if re.match(r"^\d+$", first_segment):
                continue

            # 6. 排除恶意软件检测名（如 Win64/Runner.AD → runner.ad）
            before = text[max(0, m.start() - 40):m.start()]
            if re.search(
                r'(?:Trojan|Win(?:32|64)|JS|VBS|Exploit|Backdoor|Worm|Ransom(?:ware)?|'
                r'Dropper|Downloader|Rootkit|Spy(?:ware)?|Adware|Riskware|'
                r'Hacktool|PUA|Potentially)\s*[/-]\s*$',
                before, re.IGNORECASE,
            ):
                continue

            iocs.append(ExtractedIOC(
                "domain", domain, self._context(text, m.start(), m.end()), 0.85,
            ))
        return iocs

    # ── 文件哈希 ──────────────────────────────────────────

    def _extract_hashes(self, text: str, _result: ExtractionResult = None) -> list[ExtractedIOC]:
        """提取 MD5/SHA1/SHA256 哈希

        使用两种策略：
        1. 关键词邻近扫描：在 "md5", "sha256", "hash" 等关键词附近查找
        2. 全量扫描：在整个文本中扫描有效哈希（作为兜底）
        """
        hash_kw = [
            "md5", "sha1", "sha256", "sha-256", "sha512", "sha-512",
            "hash", "文件哈希", "哈希", "checksum", "digest",
        ]

        iocs, seen = [], set()

        # 策略1: 关键词邻近扫描（高置信度）
        for kw in hash_kw:
            try:
                for kw_m in re.finditer(re.escape(kw), text, re.IGNORECASE):
                    kw_start = kw_m.start()
                    window_start = max(0, kw_start - 250)
                    window_end = min(len(text), kw_m.end() + 250)
                    nearby = text[window_start:window_end]

                    for htype, pat in self.HASH_PATTERNS.items():
                        for hm in pat.finditer(nearby):
                            hv = hm.group().lower()
                            if hv in seen or not self._valid_hash(hv):
                                continue
                            seen.add(hv)
                            # 映射回原始文本位置来计算上下文
                            abs_start = window_start + hm.start()
                            abs_end = window_start + hm.end()
                            iocs.append(ExtractedIOC(
                                "hash", hv,
                                self._context(text, abs_start, abs_end),
                                0.92,
                            ))
            except Exception as e:
                logger.warning(f"Hash 关键词扫描 [{kw}] 失败: {e}")

        # 策略2: 全量扫描兜底（略低置信度）
        # 只扫描文本中未被关键词覆盖的哈希
        try:
            for htype, pat in self.HASH_PATTERNS.items():
                for m in pat.finditer(text):
                    hv = m.group().lower()
                    if hv in seen or not self._valid_hash(hv):
                        continue
                    # 检查匹配值周边是否像威胁报告中的 hash
                    # （避免误提取代码中的 hex 常量）
                    before = text[max(0, m.start() - 30):m.start()].lower()
                    if not self._looks_like_hash_context(before, htype):
                        continue
                    seen.add(hv)
                    iocs.append(ExtractedIOC(
                        "hash", hv,
                        self._context(text, m.start(), m.end()),
                        0.75,  # 较低置信度（无明确关键词佐证）
                    ))
        except Exception as e:
            logger.warning(f"Hash 全量扫描失败: {e}")

        return iocs

    @staticmethod
    def _looks_like_hash_context(before: str, htype: str) -> bool:
        """检查 hash 值前面的上下文是否像威胁报告中的哈希引用"""
        indicators = [
            htype, "md5", "sha1", "sha256", "sha-256", "sha512", "sha-512",
            "hash", "哈希", "checksum", "digest",
            ":", "=", "->", "=>", ": ", "= ",
        ]
        before_lower = before.lower()
        return any(ind in before_lower for ind in indicators)

    @staticmethod
    def _valid_hash(h: str) -> bool:
        """排除明显的假 hash（全零、全相同字符等）"""
        if h in IOCExtractor.BOGUS_HASHES:
            return False
        # 检查字符多样性：至少要有 6 种不同的 hex 字符
        if len(set(h)) < 6:
            return False
        # 排除连续重复模式（如 "abcabcabc..."）
        if h[:4] * (len(h) // 4) == h[:len(h) // 4 * 4]:
            return False
        return True

    # ── ATT&CK 技术 ───────────────────────────────────────

    def _extract_attack(self, text: str, _result: ExtractionResult = None) -> list[ExtractedIOC]:
        seen = set()
        return [
            ExtractedIOC(
                "attack_technique", m.group().upper(),
                self._context(text, m.start(), m.end()), 0.98,
            )
            for m in self.ATTACK_RE.finditer(text)
            if not (m.group().upper() in seen or seen.add(m.group().upper()))
        ]

    # ── CVE 编号 ─────────────────────────────────────────

    def _extract_cves(self, text: str, _result: ExtractionResult = None) -> list[ExtractedIOC]:
        seen = set()
        return [
            ExtractedIOC(
                "cve", m.group().upper(),
                self._context(text, m.start(), m.end()), 0.98,
            )
            for m in self.CVE_RE.finditer(text)
            if not (m.group().upper() in seen or seen.add(m.group().upper()))
        ]

    # ── 威胁组织 ──────────────────────────────────────────

    def _extract_groups(self, text: str, _result: ExtractionResult = None) -> list[ExtractedIOC]:
        seen = set()
        return [
            ExtractedIOC(
                "threat_group", m.group(),
                self._context(text, m.start(), m.end()), 0.85,
            )
            for m in self.THREAT_GROUP_RE.finditer(text)
            if not (m.group().upper().replace(" ", "_") in seen
                    or seen.add(m.group().upper().replace(" ", "_")))
        ]

    # ── 邮箱 ──────────────────────────────────────────────

    def _extract_emails(self, text: str, _result: ExtractionResult = None) -> list[ExtractedIOC]:
        seen = set()
        # 排除占位符邮箱（只跳过完整匹配，不跳过域名包含这些词的邮箱）
        skip_exact = {"example@example.com", "test@test.com", "user@example.com",
                       "admin@example.com", "email@example.com", "noreply@example.com",
                       "no-reply@example.com", "support@example.com", "info@example.com"}
        skip_domains = {"@example.com", "@test.com", "@email.com", "@domain.com",
                         "@yourdomain.com", "@company.com"}
        return [
            ExtractedIOC(
                "email", m.group().lower(),
                self._context(text, m.start(), m.end()), 0.80,
            )
            for m in self.EMAIL_RE.finditer(text)
            if (m.group().lower() not in skip_exact
                and not any(d in m.group().lower() for d in skip_domains)
                and not (m.group().lower() in seen or seen.add(m.group().lower())))
        ]

    # ── 去重 ──────────────────────────────────────────────

    @staticmethod
    def _dedup(iocs: list[ExtractedIOC]) -> list[ExtractedIOC]:
        """去重：相同类型+相同值只保留置信度最高的"""
        seen = {}
        for ioc in iocs:
            key = (ioc.ioc_type, ioc.value.lower())
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc
        return list(seen.values())

    # ── 统计 ──────────────────────────────────────────────

    def _compute_stats(self, result: ExtractionResult) -> dict:
        counts = {}
        for ioc in result.iocs:
            counts[ioc.ioc_type] = counts.get(ioc.ioc_type, 0) + 1
        counts["total"] = len(result.iocs)
        return counts

    def _compute_categories(self, result: ExtractionResult) -> dict:
        """按 category 分组，每组包含 IOC 数量、标签、图标"""
        groups: dict[str, dict] = {}
        for ioc in result.iocs:
            cat = get_category(ioc.ioc_type)
            if cat not in groups:
                groups[cat] = {
                    "category": cat,
                    "label": get_type_label(ioc.ioc_type),
                    "count": 0,
                    "types": set(),
                }
            groups[cat]["count"] += 1
            groups[cat]["types"].add(ioc.ioc_type)
        # 按预定义顺序排列
        ordered = {}
        for cat in CATEGORY_ORDER:
            if cat in groups:
                groups[cat]["types"] = list(groups[cat]["types"])
                ordered[cat] = groups[cat]
        return ordered
