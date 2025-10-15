from random import Random

from src.utils.models import LogRow
import random
import calendar
import socket
import struct
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

dictionary = {'request': ['GET', 'POST', 'PUT', 'DELETE'],
              'statuscode': ['404'],
              'ua': ['Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0',
                     'Mozilla/5.0 (Android 10; Mobile; rv:84.0) Gecko/84.0 Firefox/84.0',
                     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36',
                     'Mozilla/5.0 (Linux; Android 10; ONEPLUS A6000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Mobile Safari/537.36',
                     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4380.0 Safari/537.36 Edg/89.0.759.0',
                     'Mozilla/5.0 (Linux; Android 10; ONEPLUS A6000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.116 Mobile Safari/537.36 EdgA/45.12.4.5121',
                     'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 OPR/73.0.3856.329',
                     'Mozilla/5.0 (Linux; Android 10; ONEPLUS A6000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Mobile Safari/537.36 OPR/61.2.3076.56749',
                     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
                     'Mozilla/5.0 (iPhone; CPU iPhone OS 12_4_9 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1'],
              'referrer': ['-']}

LOG_RE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"(?: (?P<duration>\d+))?\s*$'
)


def parse_line(line: str) -> Optional[LogRow]:
    m = LOG_RE.match(line)
    if not m:
        return None
    req = m.group("request") or ""
    parts = req.split()
    method, path, proto = (parts + ["", "", ""])[:3]
    return LogRow(
        line_no=None,
        ip=m.group("ip"),
        time=m.group("time"),
        method=method,
        path=path,
        protocol=proto,
        status=m.group("status"),
        size=m.group("size"),
        referer=m.group("referer"),
        ua=m.group("ua"),
    )


APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_apache_time(timestr: str) -> datetime:
    return datetime.strptime(timestr, APACHE_TIME_FMT)


def format_apache_time(dt: datetime) -> str:
    return dt.strftime(APACHE_TIME_FMT)


def get_datetime_from_line(line: str) -> Optional[datetime]:
    if not line:
        return None
    parsed = parse_line(line)
    if parsed is None:
        return None
    try:
        return parse_apache_time(parsed.time)
    except Exception:
        return None


def random_time_between(
        prev_dt: Optional[datetime],
        next_dt: Optional[datetime],
        rng: random.Random,
        min_delta_if_missing: float = 0.001,
        max_delta_if_missing: float = 2.0
) -> datetime:
    if prev_dt is not None and next_dt is not None:
        if prev_dt > next_dt:
            prev_dt, next_dt = next_dt, prev_dt
        span = (next_dt - prev_dt).total_seconds()
        if span <= 0:
            jitter = rng.uniform(0.0, 1.0)
            return prev_dt + timedelta(seconds=jitter)
        t = rng.uniform(0.0, span)
        return prev_dt + timedelta(seconds=t)
    if prev_dt is not None:
        delta = rng.uniform(min_delta_if_missing, max_delta_if_missing)
        return prev_dt + timedelta(seconds=delta)
    if next_dt is not None:
        delta = rng.uniform(min_delta_if_missing, max_delta_if_missing)
        return next_dt - timedelta(seconds=delta)
    return random_apache_time(rng=rng)


def random_apache_time(start: datetime | None = None,
                       end: datetime | None = None,
                       tz: timezone = timezone.utc,
                       rng: Random = random.Random) -> datetime:
    end = end or datetime.now(tz)
    start = start or (end - timedelta(days=365))

    delta_seconds = int((end - start).total_seconds())
    moment = start + timedelta(seconds=rng.randint(0, delta_seconds))
    moment = moment.astimezone(tz)
    return moment


def build_log_line_with_payload(payload: str,
                                line_no: int | None = None,
                                seed: int = random.randint(0, 1000000),
                                time: str | None = None,
                                line_before: str | None = None,
                                line_after: str | None = None) -> LogRow:
    rng = random.Random(seed)

    moment = random_time_between(get_datetime_from_line(line_before),
                                 get_datetime_from_line(line_after),
                                 rng=rng, )
    month = calendar.month_abbr[moment.month]

    return LogRow(
        line_no=line_no,
        ip=socket.inet_ntoa(struct.pack('>I', rng.randint(1, 0xffffffff))),
        time=time or f"{moment.day:02d}/{month}/{moment.year}:{moment:%H:%M:%S} {moment:%z}",
        method=rng.choice(dictionary['request']),
        path=payload,
        protocol="HTTP/1.0",
        status=rng.choice(dictionary['statuscode']),
        size=str(int(rng.gauss(5000, 50))),
        referer=rng.choice(dictionary['referrer']),
        ua=rng.choice(dictionary['ua'])
    )
