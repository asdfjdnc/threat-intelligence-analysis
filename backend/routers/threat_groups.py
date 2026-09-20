"""威胁组织路由 — GET /api/threat-groups"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db
from models import ThreatGroup

router = APIRouter()

# 默认组织列表 — 用于初始化
DEFAULT_GROUPS = [
    {"name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "Strontium", "Sednit"],
     "origin": "俄罗斯", "threat_level": "high", "description": "GRU 支持的 APT 组织，主要针对政府和军事目标",
     "first_active": "2007", "targeted_sectors": ["政府", "军事", "外交"]},
    {"name": "APT41", "aliases": ["Winnti", "Barium", "Wicked Panda", "Double Dragon"],
     "origin": "中国", "threat_level": "high", "description": "双用途 APT 组织，间谍活动与供应链攻击并重",
     "first_active": "2012", "targeted_sectors": ["游戏", "金融", "科技"]},
    {"name": "Lazarus Group", "aliases": ["APT38", "Hidden Cobra", "BlueNoroff", "Andariel"],
     "origin": "朝鲜", "threat_level": "high", "description": "以金融攻击和间谍活动闻名的多功能 APT",
     "first_active": "2009", "targeted_sectors": ["加密货币", "金融", "政府"]},
    {"name": "APT29", "aliases": ["Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard"],
     "origin": "俄罗斯", "threat_level": "high", "description": "SVR 支持，以供应链和云服务攻击著称",
     "first_active": "2010", "targeted_sectors": ["政府", "科技", "医疗"]},
    {"name": "Kimsuky", "aliases": ["APT37", "Thallium", "Black Banshee", "Velvet Chollima"],
     "origin": "朝鲜", "threat_level": "high", "description": "主要针对韩国政府和智库",
     "first_active": "2012", "targeted_sectors": ["政府", "智库", "媒体"]},
    {"name": "APT33", "aliases": ["Elfin", "Magnallium", "Refined Kitten"],
     "origin": "伊朗", "threat_level": "medium", "description": "针对航空和能源行业的 APT 组织",
     "first_active": "2015", "targeted_sectors": ["航空", "能源"]},
    {"name": "APT34", "aliases": ["OilRig", "Helix Kitten", "Greenbug"],
     "origin": "伊朗", "threat_level": "medium", "description": "针对金融和政府的中东目标",
     "first_active": "2014", "targeted_sectors": ["金融", "政府"]},
    {"name": "Turla", "aliases": ["Snake", "Venomous Bear", "Uroburos", "Waterbug"],
     "origin": "俄罗斯", "threat_level": "high", "description": "以隐蔽卫星通信和 rootkit 著称",
     "first_active": "2008", "targeted_sectors": ["政府", "军事", "外交"]},
]


def _seed_default_groups(db: Session):
    """如果 ThreatGroup 表为空，填充默认数据"""
    if db.query(ThreatGroup).count() == 0:
        for g in DEFAULT_GROUPS:
            db.add(ThreatGroup(**g))
        db.commit()


@router.get("/threat-groups")
def list_threat_groups(
    search: str = Query(None),
    db: Session = Depends(get_db),
):
    """获取威胁组织列表"""
    _seed_default_groups(db)

    query = db.query(ThreatGroup).order_by(ThreatGroup.name)

    if search:
        like = f"%{search}%"
        query = query.filter(
            ThreatGroup.name.ilike(like)
        )

    groups = query.all()

    return [
        {
            "id": g.id,
            "name": g.name,
            "aliases": g.aliases or [],
            "description": g.description,
            "origin": g.origin,
            "threatLevel": g.threat_level,
            "firstActive": g.first_active,
            "targetedSectors": g.targeted_sectors or [],
        }
        for g in groups
    ]
