# Copyright 2026 R A Veeraragavan

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, 
# publish, distribute, sublicense, and/or sell copies of the Software, and to permit 
# persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
# BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


"""Flask-Firewall: A comprehensive firewall module for Flask applications.

This module provides stateless ACL (Access Control List) rules and stateful
connection tracking to protect Flask applications from unauthorized network access.
It includes packet filtering, rule evaluation, logging, and statistics monitoring.

Key Components:
    - RuleEngine: Evaluates packets against defined rules in order.
    - StatefulEngine: Tracks connections to allow return traffic for established sessions.
    - Logger: Dedicated logging for firewall events with ANSI stripping.
    - Firewall: Main Flask integration class that applies filtering to routes.
    - A monitor for the firewall.
    _(refere the documentation)_
"""

from .firewall import *