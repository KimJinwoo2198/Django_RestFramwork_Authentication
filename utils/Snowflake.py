import time
import threading
import random


class SnowflakeGenerator:
    """
    Snowflake 알고리즘 기반의 고유 ID 생성기.
    용도별 자릿수를 지정하고, 프로덕션 수준의 성능과 확장성을 제공합니다.
    """

    def __init__(self, worker_id, epoch=1609459200000):
        """
        초기화.
        - worker_id: Worker ID (0~1023 범위)
        - epoch: 기준 시간 (기본값: 2021-01-01 00:00:00 UTC)
        """
        if worker_id < 0 or worker_id >= (1 << 10):
            raise ValueError("Worker ID는 0과 1023 사이여야 합니다.")

        self.worker_id = worker_id
        self.epoch = epoch
        self.lock = threading.Lock()
        self.last_timestamp = -1
        self.sequence = 0

        # 비트 구성
        self.timestamp_bits = 41
        self.worker_id_bits = 10
        self.sequence_bits = 12

        self.max_sequence = (1 << self.sequence_bits) - 1
        self.max_worker_id = (1 << self.worker_id_bits) - 1
        self.timestamp_shift = self.worker_id_bits + self.sequence_bits
        self.worker_id_shift = self.sequence_bits

    def _timestamp(self):
        """현재 타임스탬프 반환 (밀리초 단위)."""
        return int(time.time() * 1000)

    def _wait_for_next_millisecond(self, last_timestamp):
        """다음 밀리초까지 대기."""
        timestamp = self._timestamp()
        while timestamp <= last_timestamp:
            timestamp = self._timestamp()
        return timestamp

    def get_id(self, digits=None):
        """
        고유한 Snowflake ID를 생성합니다.
        - digits: 생성할 ID의 자릿수 (10~19, None일 경우 기본 64비트 ID 반환)
        """
        with self.lock:
            current_timestamp = self._timestamp() - self.epoch

            if current_timestamp < 0:
                raise Exception("현재 시간이 Epoch 이전입니다.")
            if current_timestamp >= (1 << self.timestamp_bits):
                raise Exception("타임스탬프가 41비트를 초과했습니다.")

            # 동일 밀리초에서 Sequence 증가
            if current_timestamp == self.last_timestamp:
                self.sequence = (self.sequence + 1) & self.max_sequence
                if self.sequence == 0:  # Sequence 초과 시 다음 밀리초 대기
                    current_timestamp = self._wait_for_next_millisecond(self.last_timestamp)
            else:
                self.sequence = 0

            self.last_timestamp = current_timestamp

            # 64비트 Snowflake ID 생성
            snowflake_id = (
                (current_timestamp << self.timestamp_shift)
                | (self.worker_id << self.worker_id_shift)
                | self.sequence
            )

            if digits:
                # 자릿수 범위 제한
                if digits < 10 or digits > 19:
                    raise ValueError("ID 자릿수는 10에서 19 사이여야 합니다.")
                # 지정된 자릿수로 변환
                min_value = 10 ** (digits - 1)
                max_value = 10 ** digits - 1
                snowflake_id = snowflake_id % (max_value - min_value + 1) + min_value

            return snowflake_id

    def decompose_id(self, snowflake_id):
        """
        Snowflake ID를 구성 요소로 분해합니다.
        """
        sequence_mask = (1 << self.sequence_bits) - 1
        worker_id_mask = (1 << self.worker_id_bits) - 1

        sequence = snowflake_id & sequence_mask
        worker_id = (snowflake_id >> self.worker_id_shift) & worker_id_mask
        timestamp = snowflake_id >> self.timestamp_shift

        return {
            "timestamp": timestamp + self.epoch,
            "worker_id": worker_id,
            "sequence": sequence,
        }