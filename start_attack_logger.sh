#!/bin/bash
# Запуск Attack Logger в фоне
cd /home/kali/Downloads/orchid-main/orchid-perfect
nohup python3 scripts/attack_logger_service.py > /tmp/attack_logger.log 2>&1 &
echo "✅ Attack Logger запущен (порт 8014)"
echo "📊 Логи: tail -f /tmp/attack_logger.log"
echo "💀 Тест: curl -X POST http://localhost:8014/log -H 'Content-Type: application/json' -d '{\"attack_type\":\"test\",\"source_ip\":\"1.2.3.4\",\"endpoint\":\"/test\",\"payload\":\"test\"}'"
