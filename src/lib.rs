use std::collections::VecDeque;

/// 数据帧头字节 1
pub const HEADER_1: u8 = 0xFF;
/// 数据帧头字节 2
pub const HEADER_2: u8 = 0xFB;
/// 协议命令: 读取数据
pub const CMD_DATA: u8 = 0x05;

/// 一帧解析后的协议数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolFrame {
    pub cmd: u8,
    pub payload: Vec<u8>,
}

/// 长度字段解释模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthMode {
    /// 严格按协议描述: 长度表示“从长度字节开始到帧尾”的总字节数。
    /// 完整帧长度 = 2(帧头) + length。
    FromLengthByte,
    /// 兼容模式: 长度表示“从 cmd 到 CRC16”的总字节数。
    /// 完整帧长度 = 2(帧头) + 1(长度) + length。
    FromCmdByte,
}

/// 串口接收 + 协议解析器。
#[derive(Debug)]
pub struct SerialProtocolReceiver {
    rx_buf: VecDeque<u8>,
    length_mode: LengthMode,
}

impl Default for SerialProtocolReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialProtocolReceiver {
    /// 默认使用严格模式（长度从长度字节开始计数）。
    pub fn new() -> Self {
        Self {
            rx_buf: VecDeque::new(),
            length_mode: LengthMode::FromLengthByte,
        }
    }

    /// 指定长度解释模式。
    pub fn with_length_mode(length_mode: LengthMode) -> Self {
        Self {
            rx_buf: VecDeque::new(),
            length_mode,
        }
    }

    /// 将串口收到的字节流写入解析器, 返回本次成功解析出的所有帧。
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<ProtocolFrame> {
        self.rx_buf.extend(bytes.iter().copied());

        let mut frames = Vec::new();
        loop {
            let Some(frame) = self.try_parse_one() else {
                break;
            };
            frames.push(frame);
        }
        frames
    }

    fn try_parse_one(&mut self) -> Option<ProtocolFrame> {
        self.align_header();
        if self.rx_buf.len() < 3 {
            return None;
        }

        let len_field = self.rx_buf[2] as usize;
        let full_len = match self.length_mode {
            LengthMode::FromLengthByte => {
                if len_field < 4 {
                    // 长度至少要包含: 长度(1)+cmd(1)+crc16(2)
                    self.rx_buf.pop_front();
                    return None;
                }
                2 + len_field
            }
            LengthMode::FromCmdByte => {
                if len_field < 3 {
                    // 至少需要 cmd(1) + crc16(2)
                    self.rx_buf.pop_front();
                    return None;
                }
                3 + len_field
            }
        };

        if self.rx_buf.len() < full_len {
            return None;
        }

        let frame: Vec<u8> = self.rx_buf.iter().take(full_len).copied().collect();
        let crc_pos = full_len - 2;

        let expected_crc = u16::from_le_bytes([frame[crc_pos], frame[crc_pos + 1]]);
        let calc_crc = crc16_modbus(&frame[2..crc_pos]); // 从长度字节开始计算 CRC

        if expected_crc != calc_crc {
            self.rx_buf.pop_front();
            return None;
        }

        for _ in 0..full_len {
            self.rx_buf.pop_front();
        }

        let cmd = frame[3];
        let payload = frame[4..crc_pos].to_vec();

        Some(ProtocolFrame { cmd, payload })
    }

    fn align_header(&mut self) {
        while self.rx_buf.len() >= 2 {
            if self.rx_buf[0] == HEADER_1 && self.rx_buf[1] == HEADER_2 {
                break;
            }
            self.rx_buf.pop_front();
        }
    }
}

/// CRC16(MODBUS) 计算。
/// 多项式 0xA001, 初值 0xFFFF, 低字节在前。
pub fn crc16_modbus(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// 按“长度从长度字节开始计数”构造协议帧（严格协议模式）。
pub fn build_frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let len = 1 + 1 + payload.len() + 2; // len + cmd + payload + crc16
    let mut out = Vec::with_capacity(2 + len);
    out.extend([HEADER_1, HEADER_2, len as u8, cmd]);
    out.extend(payload);
    let crc = crc16_modbus(&out[2..]);
    out.extend(crc.to_le_bytes());
    out
}

/// 按“长度从 cmd 开始计数”构造协议帧（兼容旧设备）。
pub fn build_legacy_frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let len = 1 + payload.len() + 2; // cmd + payload + crc16
    let mut out = Vec::with_capacity(3 + len);
    out.extend([HEADER_1, HEADER_2, len as u8, cmd]);
    out.extend(payload);
    let crc = crc16_modbus(&out[2..]);
    out.extend(crc.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_strict_protocol_mode() {
        // 严格模式: FF FB 05 05 01 CRC16
        let frame = build_frame(CMD_DATA, &[0x01]);
        assert_eq!(frame[0], 0xFF);
        assert_eq!(frame[1], 0xFB);
        assert_eq!(frame[2], 0x05);
        assert_eq!(frame[3], 0x05);
        assert_eq!(frame[4], 0x01);

        let mut rx = SerialProtocolReceiver::new();
        let parsed = rx.feed(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].cmd, CMD_DATA);
        assert_eq!(parsed[0].payload, vec![0x01]);
    }

    #[test]
    fn parse_legacy_example_ff_fb_04_05_01_crc16() {
        // 兼容模式: FF FB 04 05 01 CRC16
        let frame = build_legacy_frame(CMD_DATA, &[0x01]);
        assert_eq!(frame[2], 0x04);

        let mut rx = SerialProtocolReceiver::with_length_mode(LengthMode::FromCmdByte);
        let parsed = rx.feed(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].cmd, CMD_DATA);
        assert_eq!(parsed[0].payload, vec![0x01]);
    }

    #[test]
    fn parse_with_noise_and_fragmented_input() {
        let frame = build_frame(CMD_DATA, &[0x01]);

        let mut rx = SerialProtocolReceiver::new();
        let mut parsed = rx.feed(&[0x00, 0x11, 0x22, 0xFF]);
        assert!(parsed.is_empty());

        parsed = rx.feed(&frame[1..3]);
        assert!(parsed.is_empty());

        parsed = rx.feed(&frame[3..]);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].payload, vec![0x01]);
    }

    #[test]
    fn crc_error_is_rejected() {
        let mut frame = build_frame(CMD_DATA, &[0x01]);
        let end = frame.len() - 1;
        frame[end] ^= 0xFF;

        let mut rx = SerialProtocolReceiver::new();
        let parsed = rx.feed(&frame);
        assert!(parsed.is_empty());
    }
}
