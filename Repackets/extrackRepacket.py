import re

def extract_to_openkore():
    input_file = r'C:\Users\User\Downloads\sidebyside\Repackets\bamboo_analysis.txt'
    output_file = r'C:\Users\User\Downloads\sidebyside\Repackets\recvpackets.txt'
    packets = {}

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                # ใช้ Regex ค้นหา ID: XXXX และ Len: DDD
                match = re.search(r'ID:\s+([0-9a-fA-F]{4}).*?Len:\s+(\(?-?\d+\)?)', line)
                if match:
                    p_id = match.group(1).upper()
                    p_len = match.group(2)
                    
                    # เก็บลง dictionary เพื่อป้องกัน ID ซ้ำกัน (ใช้ค่าล่าสุด)
                    packets[p_id] = p_len

        # เขียนไฟล์ออกในรูปแบบ OpenKore
        with open(output_file, 'w', encoding='utf-8') as f:
            # เรียงลำดับ ID จากน้อยไปมาก
            for p_id in sorted(packets.keys()):
                f.write(f"{p_id} {packets[p_id]}\n")

        print(f"✅ แปลงสำเร็จ! พบทั้งหมด {len(packets)} packets")
        print(f"📁 บันทึกเป็นไฟล์: {output_file}")

    except FileNotFoundError:
        print(f"❌ ไม่พบไฟล์ {input_file} กรุณาตรวจสอบชื่อไฟล์อีกครั้ง")

if __name__ == "__main__":
    extract_to_openkore()
