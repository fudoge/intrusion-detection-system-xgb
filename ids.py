import csv
import sys
from datetime import datetime

import numpy as np
import xgboost as xgb
from scapy.all import IP, TCP, sniff

args = sys.argv
if len(args) != 2:
    print("Usage: sudo python3 ids.py <Interface>")
    exit(1)


# 모델 불러오기
model = xgb.Booster()
model.load_model("model.json")

# 현재 시간 기준으로 플로우 정보 csv파일 생성
current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
filename = f"{current_time}.csv"
file = open(filename, mode="a", encoding="utf-8")
writer = csv.writer(file)

# 로그파일 생성
logfilename = f"log-{current_time}.txt"
logfile = open(logfilename, mode="a", encoding="utf-8")

# 특징명들
feature_names = [
    "Total_Length_of_Fwd_Packets",
    "Flow_Packets_Sec",
    "Fwd_Packet_Length_Max",
    "Bwd_Header_Length",
    "min_seg_size_forward",
    "Max_Packet_Length",
    "act_data_pkt_fwd",
    "Flow_IAT_Min",
    "Init_Win_bytes_backward",
    "Total_Backward_Packets",
]
# csv파일의 첫줄에는 특징명들과 라벨을 달아줌
writer.writerow(
    [
        "Total_Length_of_Fwd_Packets",
        "Flow_Packets_Sec",
        "Fwd_Packet_Length_Max",
        "Bwd_Header_Length",
        "min_seg_size_forward",
        "Max_Packet_Length",
        "act_data_pkt_fwd",
        "Flow_IAT_Min",
        "Init_Win_bytes_backward",
        "Total_Backward_Packets",
        "Label",
    ]
)
# Selected Features:
# Total_Length_of_Fwd_Packets - 전방향 패킷의 총 길이
# Flow_Packets_Sec - 초당 패킷수
# Fwd_Packet_Length_Max - 전방향 패킷 최대 길이
# Bwd_Header_Length - 역방향 헤더 길이 총합
# min_seg_size_forward - 전방향 세그먼트 사이즈 최소값
# Max_Packet_Length - 패킷 최대 길이
# act_data_pkt_fwd - 페이로드를 포함하는 전방향 패킷의 개수
# Flow_IAT_Min - 두 패킷 사이의 시간 간격
# Init_Win_bytes_backward - 역방향 최초 윈도우 바이트
# Total_Backward_Packets - 총 역방향 패킷수


# FlowData 클래스
class FlowData:
    def __init__(self):
        self.total_length_of_fwd_packets = 0  # 전방향 패킷의 총 길이
        self.fwd_packet_length_max = -1  # 전방향 패킷 최대 길이
        self.packet_counts = 0  # 패킷 수
        self.bwd_header_length = 0  # 역방향 헤더 길이 총합
        self.min_seg_size_forward = -1  # 전방향 세그먼트 사이즈 최소값(MSS in TCP)
        self.max_packet_length = 0  # 최대 패킷 길이
        self.act_data_pkt_fwd = 0  # 페이로드를 포함하는 전방향 패킷의 수
        self.iat_min = -1  # 패킷간 시간간격 최소값
        self.init_win_bytes_backward = -1  # 역방향 최초 윈도우 바이트
        self.total_backward_packets = 0
        self.first_timestamp = 0  # 첫패킷 타임스탬프
        self.last_timestamp = 0  # 마지막패킷 타임스탬프
        self.flow_state = 0  # 0: BENIGN, 1: Dos Hulk, 2: Dos Slowloris
        self.state_streak = 0  # 같은 상태가 얼마나 지속되었는지
        self.frequency = 0  # 플로우 등장횟수


# flow 딕셔너리. 5-원소 튜플을 key로 하고, FlowData객체를 Value로 함.
flow_table = {}


# 패킷 처리
def process_packet(packet):
    try:
        # 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) 추출
        src_ip = packet[IP].src  # source IP 추출
        dst_ip = packet[IP].dst  # destination IP 추출
        src_port = packet[TCP].sport  # source Port 추출
        dst_port = packet[TCP].dport  # destination Port 추출
        protocol = "TCP"  # 프로토콜 추출(tcp or udp)
        packet_timestamp = packet.time  # 타임스탬프 추출
        packet_length = len(packet[IP])  # 패킷의 크기 추출
        payload_size = len(packet[TCP].payload)  # 페이로드 크기
        packet_window_size = packet[TCP].window  # 윈도우 사이즈
        header_length = (
            packet[IP].ihl + packet[TCP].dataofs
        )  # IP헤더 + TCP헤더크기(실제로는 헤더크기에 4를 곱해야 실제크기임)

        # 패킷의 방향 계산
        isForward = False
        # 만약 수신지 포트가 서버 포트이면, 전방향 패킷
        if dst_port in [8080, 80, 443]:
            isForward = True

        # 방향에 따라 튜플 생성(아래와 같이 통일하기 위해)
        # flow_tuple: server_ip, client_ip, server_port, client_port, protocol
        if isForward:
            flow_tuple = (dst_ip, src_ip, dst_port, src_port, protocol)
        else:
            flow_tuple = (src_ip, dst_ip, src_port, dst_port, protocol)

        # 플로우 테이블 관련 정보 정리
        # 플로우 테이블에 현재 튜플로 검색하여 있다면 업데이트, 아니면 초기화
        if flow_tuple in flow_table:
            flow_data = flow_table[flow_tuple]

            # 초반 패킷은 핸드셰이크로, 애플리케이션 통신의 플로우에는 잡음의 가능성 있음.
            if flow_data.frequency < 2:
                flow_data.frequency += 1
                return
            elif flow_data.frequency == 2:
                flow_data = flow_table[flow_tuple]
                flow_data.frequency += 1
                if isForward:  # 전방향인 경우
                    flow_data.total_length_of_fwd_packets = packet_length
                    flow_data.fwd_packet_length_max = packet_length
                    flow_data.packet_counts = 1
                    flow_data.min_seg_size_forward = payload_size
                    flow_data.max_packet_length = packet_length
                    flow_data.act_data_pkt_fwd = 1 if payload_size > 0 else 0
                    flow_data.first_timestamp = packet_timestamp
                    flow_data.last_timestamp = packet_timestamp
                    flow_data.fwd_header_length = header_length
                else:
                    flow_data.packet_counts = 1
                    flow_data.bwd_header_length = header_length
                    flow_data.max_packet_length = packet_length
                    flow_data.first_timestamp = packet_timestamp
                    flow_data.last_timestamp = packet_timestamp
                    flow_data.init_win_bytes_backward = packet_window_size
                    flow_data.total_backward_packets = 1
            else:  # 두 번 초과부터는 갱신..
                flow_data.frequency += 1
                # 전방향인 경우
                if isForward:
                    flow_data.total_length_of_fwd_packets += packet_length
                    flow_data.fwd_packet_length_max = max(
                        flow_data.fwd_packet_length_max, packet_length
                    )
                    flow_data.packet_counts += 1
                    if flow_data.min_seg_size_forward == -1:
                        flow_data.min_seg_size_forward = payload_size
                    else:
                        flow_data.min_seg_size_forward = min(
                            flow_data.min_seg_size_forward, payload_size
                        )
                    flow_data.max_packet_length = max(
                        flow_data.max_packet_length, packet_length
                    )
                    flow_data.act_data_pkt_fwd += 1 if payload_size > 0 else 0
                    if flow_data.iat_min == -1:
                        flow_data.iat_min = packet_timestamp - flow_data.last_timestamp
                    else:
                        flow_data.iat_min = min(
                            flow_data.iat_min,
                            packet_timestamp - flow_data.last_timestamp,
                        )
                    flow_data.last_timestamp = packet_timestamp
                else:  # 역방향인 경우
                    flow_data.packet_counts += 1
                    flow_data.bwd_header_length += header_length
                    flow_data.max_packet_length = max(
                        flow_data.max_packet_length, packet_length
                    )
                    if flow_data.iat_min == -1:
                        flow_data.iat_min = packet_timestamp - flow_data.last_timestamp
                    else:
                        flow_data.iat_min = min(
                            flow_data.iat_min,
                            packet_timestamp - flow_data.last_timestamp,
                        )
                    flow_data.last_timestamp = packet_timestamp
                    if flow_data.init_win_bytes_backward == -1:
                        flow_data.init_win_bytes_backward = packet_window_size
                    flow_data.total_backward_packets += 1
        else:
            flow_table[flow_tuple] = FlowData()  # 새로 플로우데이터 등록
            flow_table[flow_tuple].frequency += 1

        # 플로우 테이블 정보로 특징 만들기..
        flow_data = flow_table[flow_tuple]
        f_total_length_of_fwd_packets = flow_data.total_length_of_fwd_packets
        f_flow_packets_sec = flow_data.packet_counts / (
            flow_data.last_timestamp - flow_data.first_timestamp
        )
        f_fwd_packet_length_max = flow_data.fwd_packet_length_max
        f_bwd_header_length = flow_data.bwd_header_length
        f_min_seg_size_foward = flow_data.min_seg_size_forward
        f_max_packet_length = flow_data.max_packet_length
        f_act_data_pkt_fwd = flow_data.act_data_pkt_fwd
        f_flow_iat_min = flow_data.iat_min
        f_init_win_bytes_backward = flow_data.init_win_bytes_backward
        f_total_backward_packets = flow_data.total_backward_packets

        # 플로우 특징별 값을 모음
        feature_val = [
            f_total_length_of_fwd_packets,
            f_flow_packets_sec,
            f_fwd_packet_length_max,
            f_bwd_header_length,
            f_min_seg_size_foward,
            f_max_packet_length,
            f_act_data_pkt_fwd,
            f_flow_iat_min,
            f_init_win_bytes_backward,
            f_total_backward_packets,
        ]

        # 초기화된 적 없는 값이 있다면, 예측하지 않음.
        if -1 in feature_val:
            return
        # 결산된 특징의 값들로 배열 생성
        features = np.array(
            [feature_val],
            dtype=np.float64,
        )

        # 특징명들 주입해서 XGBoost 행렬 생성
        dmatrix = xgb.DMatrix(features, feature_names=feature_names)
        # 모델 예측
        res = int(model.predict(dmatrix)[0])
        # 예측값 출력 및 패킷의 방향 출력해보기
        direction = "Forward" if isForward is True else "Backward"
        print(
            "[MODEL] Prediction: "
            + str(res)
            + ", Flow Tuple: "
            + str(flow_tuple)
            + " Packet Dir: "
            + direction
        )
        # 상태의 지속 업데이트
        if res == flow_data.flow_state:
            flow_data.state_streak += 1
        else:
            flow_data.state_streak = 1
        flow_data.flow_state = res
        # 이상 상태가 7회 연속이면, print 및 로그파일 기록
        if flow_data.state_streak == 7:
            if flow_data.flow_state == 1:
                print("[WARNING] Dos Hulk Attack is suspected: " + str(flow_tuple))
                logfile.write(
                    "[WARNING] Dos Hulk Attack is suspected: "
                    + str(flow_tuple)
                    + " timestamp: "
                    + str(flow_data.last_timestamp)
                    + "\n"
                )
            elif flow_data.flow_state == 2:
                print("[WARNING] Dos Slowloris Attack is suspected: " + str(flow_tuple))
                logfile.write(
                    "[WARNING] Dos Slowloris Attack is suspected: "
                    + str(flow_tuple)
                    + " timestamp: "
                    + str(flow_data.last_timestamp)
                    + "\n"
                )

        # 플로우의 특징을 csv맨밑줄에 append
        writer.writerow(
            [
                f_total_length_of_fwd_packets,
                f_flow_packets_sec,
                f_fwd_packet_length_max,
                f_bwd_header_length,
                f_min_seg_size_foward,
                f_max_packet_length,
                f_act_data_pkt_fwd,
                f_flow_iat_min,
                f_init_win_bytes_backward,
                f_total_backward_packets,
                res,
            ]
        )

    except KeyboardInterrupt:
        print("terminate")
        logfile.flush()
        file.flush()
        logfile.close()
        file.close()
    except:
        pass


if __name__ == "__main__":
    print("Capture Started")
    sniff(iface=args[1], prn=process_packet, store=0, count=0)
