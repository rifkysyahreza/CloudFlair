import argparse

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument(
    'domain',
    help = 'The domain to scan'
)

parser.add_argument(
    '-o', '--output',
    help = 'A file to output likely origin servers to',
    dest = 'output_file'
)

parser.add_argument(
    '--censys-api-key',
    help = 'Censys Personal Access Token. Can also be defined using the CENSYS_API_KEY environment variable',
    dest = 'censys_api_key'
)

parser.add_argument(
    '--cloudfront',
    help = 'Check Cloudfront instead of CloudFlare.',
    dest = 'use_cloudfront',
    action='store_true',
    default=False
)
