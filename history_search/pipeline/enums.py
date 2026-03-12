"""Enumerations for browser engines, transition types, and visit sources."""
from enum import Enum, unique


@unique
class BrowserEngine(Enum):
    CHROMIUM = "chromium"
    GECKO = "gecko"
    WEBKIT = "webkit"


@unique
class Browser(Enum):
    CHROME = "chrome"
    SAFARI = "safari"
    FIREFOX = "firefox"
    EDGE = "edge"
    BRAVE = "brave"
    VIVALDI = "vivaldi"
    ARC = "arc"
    OPERA = "opera"
    CHROMIUM = "chromium"
    TEAMS = "teams"
    UNKNOWN = "unknown"


# Map browsers to their engines
BROWSER_ENGINE_MAP = {
    Browser.CHROME: BrowserEngine.CHROMIUM,
    Browser.EDGE: BrowserEngine.CHROMIUM,
    Browser.BRAVE: BrowserEngine.CHROMIUM,
    Browser.VIVALDI: BrowserEngine.CHROMIUM,
    Browser.ARC: BrowserEngine.CHROMIUM,
    Browser.OPERA: BrowserEngine.CHROMIUM,
    Browser.CHROMIUM: BrowserEngine.CHROMIUM,
    Browser.TEAMS: BrowserEngine.CHROMIUM,
    Browser.FIREFOX: BrowserEngine.GECKO,
    Browser.SAFARI: BrowserEngine.WEBKIT,
}


@unique
class VisitSource(Enum):
    LOCAL = "local"
    SYNCED = "synced"
    EXTENSION = "extension"
    IMPORTED = "imported"
    UNKNOWN = "unknown"


@unique
class VisitSourceConfidence(Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNKNOWN = "unknown"


@unique
class TransitionType(Enum):
    TYPED = "typed"
    LINK = "link"
    BOOKMARK = "bookmark"
    REDIRECT_PERMANENT = "redirect_permanent"
    REDIRECT_TEMPORARY = "redirect_temporary"
    FORM_SUBMIT = "form_submit"
    RELOAD = "reload"
    EMBEDDED = "embedded"
    DOWNLOAD = "download"
    GENERATED = "generated"
    KEYWORD = "keyword"
    OTHER = "other"


@unique
class OSPlatform(Enum):
    MACOS = "macos"
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


@unique
class TimeInterval(Enum):
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
