#!/usr/bin/env bash

# ============================================================
# 脚本：run_one_probe.sh
# 功能：使用 garak 对单个探针执行安全扫描
# 用法：./run_one_probe.sh <标签> <探针名> <生成次数> [随机种子]
# 示例：./run_one_probe.sh experiment malwaregen.TopLevel 3 42
# ============================================================

set -Eeuo pipefail

# -------------------- 参数读取 --------------------
if [[ $# -lt 3 ]]; then
    echo "用法：$0 <标签> <探针名称> <生成次数> [随机种子]"
    echo ""
    echo "示例："
    echo "  $0 warmup malwaregen.TopLevel 1 42"
    echo "  $0 formal malwaregen.Payload 3 0"
    exit 2
fi

LABEL="$1"
PROBE="$2"
GENERATIONS="$3"
SEED="${4:-42}"

# -------------------- 路径配置 --------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXP="$ROOT/experiments/malwaregen"
MODEL="$ROOT/models/Qwen2.5-0.5B-Instruct"
CONFIG="$EXP/config/base.yaml"

# 虚拟环境路径（可选）
VENV="${GARAK_VENV:-/root/venvs/garak-qwen}"
if [[ -f "$VENV/bin/activate" ]]; then
    source "$VENV/bin/activate"
fi

# -------------------- 环境变量 --------------------
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export TOKENIZERS_PARALLELISM=false
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"

# 创建必要的目录
mkdir -p "$EXP/logs" "$EXP/reports" "$EXP/analysis"

# -------------------- 探针白名单校验 --------------------
case "$PROBE" in
    malwaregen.TopLevel|malwaregen.Payload|malwaregen.SubFunctions)
        ;;
    malwaregen.Evasion|malwaregen)
        echo "[错误] 本实验排除的探针：$PROBE"
        exit 3
        ;;
    *)
        echo "[错误] 不支持的探针名称：$PROBE"
        exit 3
        ;;
esac

# -------------------- 模型文件检查 --------------------
if [[ ! -f "$MODEL/config.json" ]]; then
    echo "[错误] 模型文件不存在：$MODEL"
    exit 4
fi

# -------------------- 依赖检查 --------------------
python -c "import garak, torch, transformers" || {
    echo "[错误] Python环境缺少garak/torch/transformers依赖"
    exit 5
}

# -------------------- 执行扫描 --------------------
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
PROBE_SHORT="${PROBE#malwaregen.}"
RUN_ID="${LABEL}_${PROBE_SHORT}_g${GENERATIONS}_s${SEED}_${TIMESTAMP}"
CONSOLE_LOG="$EXP/logs/${RUN_ID}.console.log"

echo ""
echo "=================================================="
echo "  garak 安全测评"
echo "=================================================="
echo "  运行编号  : $RUN_ID"
echo "  实验标签  : $LABEL"
echo "  目标模型  : $MODEL"
echo "  探针名称  : $PROBE"
echo "  生成次数  : $GENERATIONS"
echo "  随机种子  : $SEED"
echo "  报告目录  : $EXP/reports"
echo "=================================================="
echo ""

set +e
set -o pipefail

/usr/bin/time -v \
python -m garak \
    --config "$CONFIG" \
    --target_type huggingface \
    --target_name "$MODEL" \
    --probes "$PROBE" \
    --generations "$GENERATIONS" \
    --seed "$SEED" \
    --report_prefix "$RUN_ID" \
    2>&1 | tee "$CONSOLE_LOG"

RUN_STATUS=${PIPESTATUS[0]}
set -e

# -------------------- 结果汇总 --------------------
echo ""
echo "=================================================="
echo " 扫描完成"
echo "=================================================="
echo "  退出状态  : $RUN_STATUS"
echo "  控制台日志: $CONSOLE_LOG"
echo ""

REPORT_FILE="$(find "$EXP/reports" -maxdepth 1 -type f -name "${RUN_ID}*.report.jsonl" 2>/dev/null | sort | tail -n 1)"

if [[ -n "${REPORT_FILE:-}" && -f "$REPORT_FILE" ]]; then
    echo "  [成功] 报告文件: $REPORT_FILE"
    echo "$REPORT_FILE" > "$EXP/analysis/latest_${LABEL}_${PROBE_SHORT}.txt"
else
    echo "  [警告] 未找到 report.jsonl 文件"
fi

echo "=================================================="
exit "$RUN_STATUS"