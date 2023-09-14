#!/usr/bin/env python
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

NAME = '网御星云'


def is_waf(self):
    if self.matchContent(r'images/titleIcon.png'):
        return True


    return False
