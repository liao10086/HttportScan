NAME = '安恒WAF'


def is_waf(self):
    if self.matchContent(r'error-desc">因权限问题或行为非法，您的访问被拒绝。</div>'):
        return True
    if self.matchContent(r'<title>403</title>') and self.matchContent(r'font-bold">Forbidden</h3>'):
        return True

    return False
