from loguru import logger
import sys


LOGS_PATH = "logs/ocb.log"


@logger.catch
def main():
    raise NotImplementedError("Not implemented yet")


if __name__ == "__main__":
    logger.add(
        sys.stderr,
        colorize=True,
        format="{time} {level} {message}",
        filter="my_module",
        level="INFO",
    )
    logger.add(LOGS_PATH)
    main()
