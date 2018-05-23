import inspect
import logging
import time

import sys

from oidcendpoint import sanitize
from oidcendpoint.cookie import CookieDealer
from oidcendpoint.exception import ToOld

logger = logging.getLogger(__name__)


class AuthzHandling(CookieDealer):
    """ Class that allow an entity to manage authorization """

    def __init__(self, endpoint_context):
        CookieDealer.__init__(self, endpoint_context=endpoint_context)
        self.permdb = {}

    def __call__(self, *args, **kwargs):
        return ""

    def permissions(self, cookie=None, **kwargs):
        if cookie is None:
            return None
        else:
            logger.debug("kwargs: %s" % sanitize(kwargs))

            val = self.get_cookie_value(cookie,
                                        self.endpoint_context.cookie_name)
            if val is None:
                return None
            else:
                uid, _ts, typ = val

            if typ == "uam":  # shortlived
                _now = int(time.time())
                if _now > (int(_ts) + int(self.cookie_ttl * 60)):
                    logger.debug("Authentication timed out")
                    raise ToOld("%d > (%d + %d)" % (_now, int(_ts),
                                                    int(self.cookie_ttl * 60)))
            else:
                if "max_age" in kwargs and kwargs["max_age"]:
                    _now = int(time.time())
                    if _now > (int(_ts) + int(kwargs["max_age"])):
                        logger.debug("Authentication too old")
                        raise ToOld("%d > (%d + %d)" % (
                            _now, int(_ts), int(kwargs["max_age"])))

            return self.permdb[uid]


class UserInfoConsent(AuthzHandling):
    def __call__(self, user, userinfo, **kwargs):
        pass


class Implicit(AuthzHandling):
    def __init__(self, permission="implicit"):
        AuthzHandling.__init__(self)
        self.permission = permission

    def permissions(self, cookie=None, **kwargs):
        return self.permission


def factory(msgtype, **kwargs):
    """
    Factory method that can be used to easily instantiate a class instance

    :param msgtype: The name of the class
    :param kwargs: Keyword arguments
    :return: An instance of the class or None if the name doesn't match any
        known class.
    """
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, CookieDealer):
            try:
                if obj.__name__ == msgtype:
                    return obj(**kwargs)
            except AttributeError:
                pass