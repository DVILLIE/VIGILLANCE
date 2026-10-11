"""Fetch free official portable development tools; never install system software."""
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def fetch(url, limit):
    request = urllib.request.Request(url, headers={'User-Agent': 'DVielle-development-verification'})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Tool download exceeds bound')
    return data


def main():
    directory = ROOT / 'dist' / 'formal-tools-20261010'
    directory.mkdir(exist_ok=True)
    assets = json.loads(fetch('https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jre&os=windows&vendor=eclipse', 2000000))
    package = assets[0]['binary']['package']
    data = fetch(package['link'], 100000000)
    digest = hashlib.sha256(data).hexdigest()
    if digest != package['checksum']:
        raise ValueError('Official JRE checksum mismatch')
    archive = directory / package['name']
    archive.write_bytes(data)
    with zipfile.ZipFile(archive) as source:
        if len(source.infolist()) > 10000 or sum(item.file_size for item in source.infolist()) > 300000000:
            raise ValueError('JRE archive exceeds extraction bounds')
        for item in source.infolist():
            target = (directory / item.filename).resolve()
            if not target.is_relative_to(directory.resolve()) or ':' in item.filename or '\\' in item.filename:
                raise ValueError('Unsafe JRE archive path')
        source.extractall(directory)
    release = json.loads(fetch('https://api.github.com/repos/tlaplus/tlaplus/releases/latest', 2000000))
    asset = next(item for item in release['assets'] if item['name'] == 'tla2tools.jar')
    jar = fetch(asset['browser_download_url'], 20000000)
    jar_digest = hashlib.sha256(jar).hexdigest()
    published = asset.get('digest')
    if published and published != 'sha256:' + jar_digest:
        raise ValueError('Official TLA asset digest mismatch')
    (directory / 'tla2tools.jar').write_bytes(jar)
    record = {'jre': {'source': package['link'], 'sha256': digest,
        'version': assets[0]['version']['semver'], 'checksum_matched_official_api': True},
        'tla': {'source': asset['browser_download_url'], 'sha256': jar_digest,
            'version': release['tag_name'], 'official_asset_digest_matched': bool(published)},
        'system_installation': False, 'runtime_application_dependency': False}
    (ROOT / 'docs' / 'implementation' / 'FORMAL_TOOL_PROVENANCE_2026-10-10.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
