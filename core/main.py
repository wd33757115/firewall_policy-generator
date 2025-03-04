import argparse
import logging
from collections import defaultdict

import pandas as pd

from core import NetworkTopology
from policy_engine import PolicyProcessor
from vendor_config import HuaweiConfigGenerator, H3CConfigGenerator, TopSecConfigGenerator, HillstoneConfigGenerator

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="防火墙策略生成工具")
    parser.add_argument("-t", "--topology", required=True, help="拓扑JSON文件")
    parser.add_argument("-p", "--policies", required=True, help="策略Excel文件")
    parser.add_argument("-o", "--output", default="configs", help="输出目录")
    args = parser.parse_args()

    topology = NetworkTopology(args.topology)
    df = pd.read_excel(args.policies, header=None, skiprows=3,
                       names=['src_ip', 'dst_ip', 'port', 'proto', 'action'])
    print(str(df))

    ticket_id = "2025022600001"
    processor = PolicyProcessor(topology)
    all_firewall_rules = defaultdict(list)

    for idx, row in df.iterrows():
        src_ips = str(row['src_ip']).replace('，', ',').split(',')
        dst_ips = str(row['dst_ip']).replace('，', ',').split(',')
        ports = str(row['port']).replace('，', ',').split() if pd.notna(row['port']) else []
        proto = str(row['proto']) if pd.notna(row['proto']) else ''
        action = str(row['action'])
        result = processor.process_policy(src_ips, dst_ips, proto, ports, action, ticket_id)
        if result["error"]:
            logger.warning(f"策略 {idx} 处理失败: {result['error']}")
            continue

        for fw_name, fw_rules in result["firewall_rules"].items():
            for rule_key, rule_data in fw_rules.items():
                all_firewall_rules[fw_name].append({
                    'rule_key': rule_key,
                    'sources': rule_data['sources'],
                    'destinations': rule_data['destinations'],
                    'proto': rule_data['proto'],
                    'ports': rule_data['ports'],
                    'action': rule_data['action'],
                    'ticket_id': rule_data['ticket_id']
                })

    for fw_name, rules_list in all_firewall_rules.items():
        fw = topology.firewalls[fw_name]
        if fw.type == "华为":
            HuaweiConfigGenerator.generate(args.output, fw_name, rules_list)
        elif fw.type == "H3C":
            H3CConfigGenerator.generate(args.output, fw_name, rules_list)
        elif fw.type == "天融信":
            TopSecConfigGenerator.generate(args.output, fw_name, rules_list)
        elif fw.type == "山石":
            HillstoneConfigGenerator.generate(args.output, fw_name, rules_list)
        else:
            logger.error(f"不支持的防火墙类型: {fw.type}")


if __name__ == "__main__":
    main()
