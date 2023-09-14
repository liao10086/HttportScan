#!/usr/bin/env python
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

NAME = '腾讯WAF'


def is_waf(self):
    if self.matchHeader(('Server', r'TencentWAF')):
        return True

    return False