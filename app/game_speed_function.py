from .time_hook import TimeHook
import logging

logger = logging.getLogger(__name__)

# 创建全局的 TimeHook 实例
_time_hook = TimeHook()

def adjust_game_speed(game_pid: int, speed: float) -> bool:
    """调整游戏速度

    Args:
        game_pid: 游戏进程 ID
        speed: 速度倍率 (0.1-10.0)

    Returns:
        bool: 是否成功
    """
    try:
        # 如果时间函数还没有被 hook，先进行 hook
        if not _time_hook.is_active:
            _time_hook.hook_time_functions()

        # 设置新的速度倍率
        _time_hook.set_speed(speed)

        # 添加进程到影响列表
        _time_hook.add_process(game_pid)

        logger.info(f"Game speed adjusted: PID={game_pid}, speed={speed}x")
        return True

    except Exception as e:
        logger.error(f"Failed to adjust game speed: {e}")
        return False

def reset_game_speed(game_pid: int) -> bool:
    """重置游戏速度为正常

    Args:
        game_pid: 游戏进程 ID

    Returns:
        bool: 是否成功
    """
    try:
        if _time_hook.is_active:
            # 从影响列表中移除进程
            _time_hook.remove_process(game_pid)

            # 如果没有其他进程需要变速，恢复时间函数
            if not _time_hook._hooked_processes:
                _time_hook.unhook_time_functions()

        logger.info(f"Game speed reset: PID={game_pid}")
        return True

    except Exception as e:
        logger.error(f"Failed to reset game speed: {e}")
        return False

def get_current_speed(game_pid: int) -> float:
    """获取当前游戏速度

    Args:
        game_pid: 游戏进程 ID

    Returns:
        float: 当前速度倍率
    """
    if _time_hook.is_active and _time_hook.is_process_affected(game_pid):
        return _time_hook.get_speed()
    return 1.0

