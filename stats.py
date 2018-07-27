class CounterStat:
    new = int

    @staticmethod
    def apply_diff(x, y):
        return x + y


class SetStat:
    new = set

    class Diff:
        def __init__(self, added = set(), removed = set()):
            self.added = added
            self.removed = removed

        def invert(self):
            self.added, self.removed = self.removed, self.added

    @staticmethod
    def apply_diff(s, d):
        s -= d.removed
        s |= d.added
        return s


class Stats:
    stats = {
        "n_connections": CounterStat,
        "n_current_connections": CounterStat,
        "n_bytes": CounterStat,
        "n_msgs": CounterStat,
    }

    def __init__(self):
        for k, stat in type(self).stats.items():
            setattr(self, k, stat.new())

    def update(self, **kwargs):
        for k, v in kwargs.items():
            stat = type(self).stats[k]
            setattr(self, k, stat.apply_diff(getattr(self, k), v))


class UserStats(Stats):
    stats = {
        "ips": SetStat,
        **Stats.stats
    }


class IPStats(Stats):
    stats = {
        "users": SetStat,
        **Stats.stats
    }
