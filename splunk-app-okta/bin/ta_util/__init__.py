import utils
import log_files


def setup_logging_for_ta_util(loglevel="INFO", refresh=False):
    for f in log_files.get_all_logs():
        utils.setup_logging(f, loglevel, refresh)


setup_logging_for_ta_util()
