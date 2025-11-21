from bs4 import BeautifulSoup
import csv
import re
import os
import sys

def extract_task_name(html_content):
    """提取任务名称"""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # 查找任务名称
    task_name_th = soup.find('th', string='任务名称')
    if task_name_th:
        task_name_td = task_name_th.find_next_sibling('td')
        if task_name_td:
            task_name = task_name_td.get_text(strip=True)
            # 清理文件名中的非法字符
            task_name = re.sub(r'[\\/*?:"<>|]', '', task_name)
            return task_name
    
    return "漏洞报告"

def get_vuln_level(color_style):
    """根据颜色判断漏洞安全级别"""
    if not color_style:
        return "信息"
    
    if '#E42B00' in color_style:
        return "高危"
    elif '#AF6100' in color_style:
        return "中危"
    elif '#737373' in color_style:
        return "低危"
    else:
        return "信息"

def clean_text(text):
    """清理文本，去除换行符和多余空格"""
    if not text:
        return ""
    # 替换各种换行符和制表符为空格
    text = re.sub(r'[\r\n\t]+', ' ', text)
    # 合并多个连续空格
    text = re.sub(r' +', ' ', text)
    return text.strip()

def extract_all_vulnerabilities(html_content):
    """从HTML内容中提取所有漏洞信息，保持HTML中的原始顺序"""
    soup = BeautifulSoup(html_content, 'html.parser')
    vulnerabilities = []
    
    # 查找所有可能包含漏洞信息的行，保持原始顺序
    # 首先查找所有包含漏洞名称的span标签，按它们在HTML中出现的顺序
    vuln_name_spans = soup.find_all('span', style=re.compile(r'color:#'))
    
    print(f"通过颜色样式找到 {len(vuln_name_spans)} 个漏洞标题")
    
    # 按HTML中的顺序处理每个漏洞
    for span in vuln_name_spans:
        try:
            # 获取父级tr元素
            parent_tr = span.find_parent('tr')
            if not parent_tr:
                continue
                
            # 提取漏洞名称和安全级别
            vuln_name = span.get_text(strip=True)
            color_style = span.get('style', '')
            vuln_level = get_vuln_level(color_style)
            
            # 查找详细信息行
            detail_row = None
            
            # 方法1: 通过img的id查找对应的详细信息行
            img_tag = parent_tr.find('img', id=True)
            if img_tag:
                vuln_id = img_tag['id']
                detail_row = soup.find('tr', id=f"table_{vuln_id}")
            
            # 方法2: 如果没有找到，尝试查找下一个tr元素
            if not detail_row:
                next_tr = parent_tr.find_next_sibling('tr')
                if next_tr and 'more' in next_tr.get('class', []):
                    detail_row = next_tr
            
            if not detail_row:
                print(f"未找到漏洞 '{vuln_name}' 的详细信息行")
                continue
            
            # 提取所有受影响主机
            affected_hosts = "未找到主机信息"
            affected_host_th = detail_row.find('th', string='受影响主机')
            if not affected_host_th:
                # 尝试其他可能的标签文本
                possible_th_texts = ['受影响主机', '影响主机', '目标主机', 'Hosts', 'Affected Hosts']
                for text in possible_th_texts:
                    affected_host_th = detail_row.find('th', string=text)
                    if affected_host_th:
                        break
            
            if affected_host_th:
                affected_host_td = affected_host_th.find_next_sibling('td')
                if affected_host_td:
                    # 查找所有主机链接
                    host_links = affected_host_td.find_all('a', href=lambda x: x and 'host/' in x)
                    all_hosts = [link.get_text(strip=True) for link in host_links if re.match(r'\d+\.\d+\.\d+\.\d+', link.get_text(strip=True))]
                    
                    # 如果没有找到链接，尝试从文本中提取IP
                    if not all_hosts:
                        text_content = affected_host_td.get_text()
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        all_hosts = re.findall(ip_pattern, text_content)
                    
                    affected_hosts = '; '.join(all_hosts)
            
            # 提取详细描述
            description = "未找到描述信息"
            description_th = detail_row.find('th', string='详细描述')
            if not description_th:
                possible_th_texts = ['详细描述', '描述', 'Description', '漏洞描述']
                for text in possible_th_texts:
                    description_th = detail_row.find('th', string=text)
                    if description_th:
                        break
            
            if description_th:
                description_td = description_th.find_next_sibling('td')
                if description_td:
                    description = clean_text(description_td.get_text())
            
            # 提取修复建议 (原解决办法)
            solution = "未找到修复建议"
            solution_th = detail_row.find('th', string='解决办法')
            if not solution_th:
                possible_th_texts = ['解决办法', '解决方案', 'Solution', '修复建议']
                for text in possible_th_texts:
                    solution_th = detail_row.find('th', string=text)
                    if solution_th:
                        break
            
            if solution_th:
                solution_td = solution_th.find_next_sibling('td')
                if solution_td:
                    solution = clean_text(solution_td.get_text())
            
            # 添加到结果列表 - 按照指定顺序
            vulnerabilities.append({
                '安全级别': vuln_level,
                '漏洞名称': clean_text(vuln_name),
                '受影响主机': affected_hosts,
                '详细描述': description,
                '修复建议': solution
            })
            
            print(f"成功提取: {vuln_level} - {vuln_name}")
            
        except Exception as e:
            print(f"处理漏洞时出错: {e}")
            continue
    
    # 方法2: 如果方法1没有找到足够的漏洞，尝试通过类名查找
    if len(vulnerabilities) < len(vuln_name_spans):
        print("尝试通过类名查找更多漏洞...")
        
        # 查找所有可能包含漏洞信息的行
        possible_classes = ['vuln_middle', 'vuln_high', 'vuln_low', 'odd', 'even']
        
        for class_name in possible_classes:
            rows = soup.find_all('tr', class_=class_name)
            print(f"找到类名为 '{class_name}' 的行: {len(rows)} 个")
            
            for row in rows:
                try:
                    # 检查是否已经处理过这个漏洞
                    vuln_name_span = row.find('span', style=re.compile(r'color:#'))
                    if not vuln_name_span:
                        continue
                        
                    vuln_name = vuln_name_span.get_text(strip=True)
                    
                    # 检查是否已经存在
                    already_exists = any(v['漏洞名称'] == vuln_name for v in vulnerabilities)
                    if already_exists:
                        continue
                    
                    # 提取漏洞信息
                    color_style = vuln_name_span.get('style', '')
                    vuln_level = get_vuln_level(color_style)
                    
                    # 查找详细信息行
                    detail_row = None
                    img_tag = row.find('img', id=True)
                    if img_tag:
                        vuln_id = img_tag['id']
                        detail_row = soup.find('tr', id=f"table_{vuln_id}")
                    
                    if not detail_row:
                        next_tr = row.find_next_sibling('tr')
                        if next_tr and 'more' in next_tr.get('class', []):
                            detail_row = next_tr
                    
                    if not detail_row:
                        continue
                    
                    # 提取受影响主机
                    affected_hosts = "未找到主机信息"
                    affected_host_th = detail_row.find('th', string='受影响主机')
                    if affected_host_th:
                        affected_host_td = affected_host_th.find_next_sibling('td')
                        if affected_host_td:
                            host_links = affected_host_td.find_all('a', href=lambda x: x and 'host/' in x)
                            all_hosts = [link.get_text(strip=True) for link in host_links if re.match(r'\d+\.\d+\.\d+\.\d+', link.get_text(strip=True))]
                            
                            if not all_hosts:
                                text_content = affected_host_td.get_text()
                                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                                all_hosts = re.findall(ip_pattern, text_content)
                            
                            affected_hosts = '; '.join(all_hosts)
                    
                    # 提取详细描述
                    description = "未找到描述信息"
                    description_th = detail_row.find('th', string='详细描述')
                    if description_th:
                        description_td = description_th.find_next_sibling('td')
                        if description_td:
                            description = clean_text(description_td.get_text())
                    
                    # 提取修复建议 (原解决办法)
                    solution = "未找到修复建议"
                    solution_th = detail_row.find('th', string='解决办法')
                    if solution_th:
                        solution_td = solution_th.find_next_sibling('td')
                        if solution_td:
                            solution = clean_text(solution_td.get_text())
                    
                    # 添加到结果列表 - 按照指定顺序
                    vulnerabilities.append({
                        '安全级别': vuln_level,
                        '漏洞名称': clean_text(vuln_name),
                        '受影响主机': affected_hosts,
                        '详细描述': description,
                        '修复建议': solution
                    })
                    
                    print(f"通过类名找到: {vuln_level} - {vuln_name}")
                    
                except Exception as e:
                    print(f"处理类名漏洞时出错: {e}")
                    continue
    
    return vulnerabilities

def process_file(html_file):
    """处理单个文件"""
    # 验证文件是否存在
    if not os.path.exists(html_file):
        print(f"错误: 文件 '{html_file}' 不存在")
        return False
    
    # 读取HTML内容
    try:
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
    except Exception as e:
        print(f"读取文件失败: {e}")
        return False
    
    # 提取任务名称
    task_name = extract_task_name(html_content)
    print(f"任务名称: {task_name}")
    
    # 设置输出文件路径
    output_dir = os.path.dirname(html_file) or '.'
    output_file = os.path.join(output_dir, f'{task_name}.csv')
    
    # 如果文件已存在，添加序号
    counter = 1
    original_output_file = output_file
    while os.path.exists(output_file):
        output_file = os.path.join(output_dir, f'{task_name}_{counter}.csv')
        counter += 1
    
    # 提取漏洞数据
    print("正在提取漏洞信息...")
    data = extract_all_vulnerabilities(html_content)
    
    if not data:
        print("未找到任何漏洞数据")
        return False
    
    # 保存为CSV - 按照指定列顺序
    try:
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
            # 使用csv.writer确保格式正确，不包含任何格式
            writer = csv.writer(f)
            # 写入表头 - 按照指定顺序
            writer.writerow(['安全级别', '漏洞名称', '受影响主机', '详细描述', '修复建议'])
            # 写入数据 - 按照指定顺序
            for item in data:
                writer.writerow([
                    item['安全级别'],
                    item['漏洞名称'],
                    item['受影响主机'],
                    item['详细描述'],
                    item['修复建议']
                ])
        
        print(f"\n成功提取 {len(data)} 条漏洞记录")
        print(f"结果已保存到: {output_file}")
        
        # 显示统计信息
        level_count = {}
        total_hosts = 0
        
        for item in data:
            level = item['安全级别']
            level_count[level] = level_count.get(level, 0) + 1
            
            if item['受影响主机'] and item['受影响主机'] != "未找到主机信息":
                hosts = item['受影响主机'].split('; ')
                total_hosts += len(hosts)
        
        print("\n安全级别统计:")
        for level, count in sorted(level_count.items(), key=lambda x: ['高危', '中危', '低危', '信息'].index(x[0]) if x[0] in ['高危', '中危', '低危', '信息'] else 4):
            print(f"  {level}: {count} 个")
        
        print(f"总计影响 {total_hosts} 个主机实例")
        return True
        
    except Exception as e:
        print(f"保存文件时出错: {e}")
        return False

def main():
    print("=== 漏洞报告提取工具V3.0 ===")
    
    while True:
        print("\n" + "="*50)
        # 获取输入文件路径
        if len(sys.argv) > 1:
            html_file = sys.argv[1]
            # 清空sys.argv，避免下次循环还使用这个参数
            sys.argv = [sys.argv[0]]
        else:
            html_file = input("请输入HTML文件路径 (输入'quit'退出): ")
        
        # 检查是否退出
        if html_file.lower() in ['quit', 'exit', 'q']:
            print("程序已退出")
            break
        
        # 处理文件
        process_file(html_file)
        
        # 询问是否继续
        if len(sys.argv) <= 1:  # 只有在交互模式下才询问
            continue_choice = input("\n是否继续处理其他文件? (y/n): ")
            if continue_choice.lower() not in ['y', 'yes', '是']:
                print("程序已退出")
                break

if __name__ == "__main__":
    main()
    
# pyinstaller --onefile --console --name "漏洞提取工具V3.0" zhuanhuan.py