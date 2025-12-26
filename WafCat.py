import requests
import time
import json
from pathlib import Path

BASE_URL = "https://ip"  # 改成你的地址
RECORD_LIST_API = "/api/open/records"
RECORD_DETAIL_API = "/api/open/record/{}"

# 关闭 SSL 验证时屏蔽告警
requests.packages.urllib3.disable_warnings()

HEADERS = {
    "Authorization": "Bearer eyJi..."   #你的身份令牌
}

OUTPUT_DIR = Path("logs")
OUTPUT_DIR.mkdir(exist_ok=True)

TOTAL_PAGES = 405

def get_page(page):
    params = {
        "page": page,
        "page_size": 20,
        "ip": "",
        "url": "",
        "port": "",
        "host": "",
        "attack_type": "-4,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,61,62,63,64",
        "action": ""
    }
    r = requests.get(
        BASE_URL + RECORD_LIST_API,
        headers=HEADERS,
        params=params,
        timeout=10,
        verify=False  # 关闭 SSL 校验
    )
    r.raise_for_status()
    return r.json()


def get_record_detail(event_id):
    r = requests.get(
        BASE_URL + RECORD_DETAIL_API.format(event_id),
        headers=HEADERS,
        timeout=10,
        verify=False  # 关闭 SSL 校验
    )
    r.raise_for_status()
    return r.json()


def main():
    all_count = 0

    for page in range(0, TOTAL_PAGES + 1):
        print(f"[*] Fetching page {page}/{TOTAL_PAGES}")

        res = get_page(page)

        if "data" not in res or "data" not in res["data"]:
            print("[-] Invalid response format, skip.")
            continue

        records = res["data"]["data"]

        for rec in records:
            event_id = rec.get("event_id") or rec.get("EventId")
            if not event_id:
                continue

            detail = get_record_detail(event_id)

            outfile = OUTPUT_DIR / f"{event_id}.json"
            with outfile.open("w", encoding="utf-8") as fp:
                json.dump(detail, fp, ensure_ascii=False, indent=4)

            all_count += 1
            print(f"[+] Saved {event_id}")

            time.sleep(0.05)

    print(f"\n任务完成，共爬取 {all_count} 条记录。")


if __name__ == "__main__":
    main()