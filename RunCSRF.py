import core
from core.colors import green, yellow, end, run, good, info, bad, white, red
lightning = '\033[93;5m⚡\033[0m'
try:
    import concurrent.futures
    from pathlib import Path
except:
    print ('%s Bolt is not compatible with python 2. Please run it with python 3.' % bad)

try:
    from fuzzywuzzy import fuzz, process
except:
    import os
    print ('%s fuzzywuzzy library is not installed, installing now.' % info)
    os.system('pip3 install fuzzywuzzy')
    print ('%s fuzzywuzzy has been installed, please restart Bolt.' % info)
    quit()

import json
import random
import re
import statistics

from core.entropy import isRandom
from core.datanize import datanize
from core.prompt import prompt
from core.photon import photon
from core.tweaker import tweaker
from core.evaluate import evaluate
from core.ranger import ranger
from core.zetanize import zetanize
from core.requester import requester
from core.utils import extractHeaders, strength, isProtected, stringToBinary, longestCommonSubstring

def getVulner(url, level):
    target = url
    delay =  0
    timeout = 20
    threadCount = 5
    allTokens = []
    weakTokens = []
    tokenDatabase = []
    insecureForms = []
    headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip,deflate',
               'Connection': 'close', 'DNT': '1', 'Upgrade-Insecure-Requests': '1'}
    dataset = photon(target, headers, level, threadCount)
    allForms = dataset[0]
    url_list = []
    evaluate(allForms, weakTokens, tokenDatabase, allTokens, insecureForms)
    csrf_list = []
    attack = "No Vulnerable Attack Found"
    if weakTokens:
        print ('%s Weak token(s) found' % good)
        for weakToken in weakTokens:
            url = list(weakToken.keys())[0]
            token = list(weakToken.values())[0]
            print ('%s %s %s' % (info, url, token))
            url_list.append(url)
    if insecureForms:
        print ('%s Insecure form(s) found' % good)
        for insecureForm in insecureForms:
            url = list(insecureForm.keys())[0]
            action = list(insecureForm.values())[0]['action']
            form = action.replace(target, '')
            if form:
                print ('%s %s %s[%s%s%s]%s' %(bad, url, green, end, form, green, end))
                url_list.append(url)

    print (' %s Phase: Comparing %s[%s3/6%s]%s' %(lightning, green, end, green, end))
    uniqueTokens = set(allTokens)
    if len(uniqueTokens) < len(allTokens):
        print ('%s Potential Replay Attack condition found' % good)
        print ('%s Verifying and looking for the cause' % run)
        replay = False
        for each in tokenDatabase:
            url, token = next(iter(each.keys())), next(iter(each.values()))
            for each2 in tokenDatabase:
                url2, token2 = next(iter(each2.keys())), next(iter(each2.values()))
                if token == token2 and url != url2:
                    print ('%s The same token was used on %s%s%s and %s%s%s' %(good, green, url, end, green, url2, end))
                    replay = True
                    attack = "Vulnerable Attack Found"
        if not replay:
            print ('%s Further investigation shows that it was a false positive.')

    p = Path(__file__).parent.joinpath('db/hashes.json')
    with p.open('r') as f:
        hashPatterns = json.load(f)
    if not allTokens:
        print ('%s No CSRF protection to test' % bad)
        #quit()
    aToken = allTokens[0]
    matches = []
    for element in hashPatterns:
        pattern = element['regex']
        if re.match(pattern, aToken):
            for name in element['matches']:
                matches.append(pattern+"========"+name)
                csrf_list.append([pattern, name])
    if matches:
        print ('%s Token matches the pattern of following hash type(s):' % info)
    for name in matches:
        print ('    %s>%s %s' % (yellow, end, name))
    return url_list, csrf_list, attack
'''
url_list, csrf_list, attack = getVulner("https://github.com", 2)
print(url_list)
print(csrf_list)
print(attack)
'''        
