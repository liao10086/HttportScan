NAME = '安恒玄武盾'


def is_waf(self):
    if self.matchContent(r'websaas\.cn'):
        return True
    if self.matchContent(r'https://tapi\.dbappsecurity\.com\.cn/tj/tj\.min\.js'):
        return True

    return False
