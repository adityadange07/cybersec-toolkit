import os
import hashlib
import json
from datetime import datetime
from typing import Dict, Any
from pathlib import Path
from core.base_module import BaseModule

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except ImportError:
    EXIFREAD_AVAILABLE = False


class MetadataExtractor(BaseModule):
    """Extract metadata from files for forensic analysis."""

    def __init__(self):
        super().__init__("Metadata Extractor")

    def _extract_image_metadata(self, filepath: str) -> Dict:
        """Extract EXIF metadata from images."""
        metadata = {}

        if PIL_AVAILABLE:
            try:
                image = Image.open(filepath)
                metadata['format'] = image.format
                metadata['mode'] = image.mode
                metadata['size'] = {'width': image.width, 'height': image.height}

                exif_data = image._getexif()
                if exif_data:
                    metadata['exif'] = {}
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        if isinstance(value, bytes):
                            value = value.hex()
                        metadata['exif'][tag] = str(value)

                    # GPS data
                    gps_info = exif_data.get(34853)
                    if gps_info:
                        metadata['gps'] = self._parse_gps(gps_info)

            except Exception as e:
                metadata['error'] = str(e)

        elif EXIFREAD_AVAILABLE:
            try:
                with open(filepath, 'rb') as f:
                    tags = exifread.process_file(f)
                    metadata['exif'] = {str(k): str(v) for k, v in tags.items()}
            except Exception as e:
                metadata['error'] = str(e)

        return metadata

    def _parse_gps(self, gps_info: Dict) -> Dict:
        """Parse GPS coordinates from EXIF data."""
        gps = {}
        try:
            def convert_to_degrees(value):
                d = float(value[0])
                m = float(value[1])
                s = float(value[2])
                return d + (m / 60.0) + (s / 3600.0)

            if 1 in gps_info and 2 in gps_info:  # Latitude
                lat = convert_to_degrees(gps_info[2])
                if gps_info[1] == 'S':
                    lat = -lat
                gps['latitude'] = lat

            if 3 in gps_info and 4 in gps_info:  # Longitude
                lon = convert_to_degrees(gps_info[4])
                if gps_info[3] == 'W':
                    lon = -lon
                gps['longitude'] = lon

            if gps.get('latitude') and gps.get('longitude'):
                gps['google_maps'] = (
                    f"https://www.google.com/maps?q={gps['latitude']},{gps['longitude']}"
                )

        except Exception as e:
            gps['error'] = str(e)

        return gps

    def _extract_file_metadata(self, filepath: str) -> Dict:
        """Extract general file metadata."""
        stat = os.stat(filepath)
        return {
            'filename': os.path.basename(filepath),
            'full_path': os.path.abspath(filepath),
            'size_bytes': stat.st_size,
            'size_human': self._human_readable_size(stat.st_size),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'extension': Path(filepath).suffix,
            'permissions': oct(stat.st_mode),
        }

    def _compute_hashes(self, filepath: str) -> Dict:
        """Compute forensic hashes."""
        with open(filepath, 'rb') as f:
            content = f.read()
        return {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest(),
            'sha512': hashlib.sha512(content).hexdigest(),
        }

    def _human_readable_size(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024

    def _extract_pdf_metadata(self, filepath: str) -> Dict:
        """Extract metadata from PDF files."""
        metadata = {}
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                # Basic PDF metadata extraction
                import re
                info_match = re.findall(
                    rb'/(\w+)\s*\(([^)]*)\)',
                    content
                )
                for key, value in info_match:
                    metadata[key.decode()] = value.decode('utf-8', errors='ignore')
        except Exception as e:
            metadata['error'] = str(e)
        return metadata

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Extract metadata from file."""
        if not os.path.exists(target):
            return {"error": f"File not found: {target}"}

        self.logger.info(f"🔍 Extracting metadata from: {target}")

        results = {
            'file_metadata': self._extract_file_metadata(target),
            'hashes': self._compute_hashes(target),
        }

        ext = Path(target).suffix.lower()

        if ext in ['.jpg', '.jpeg', '.png', '.tiff', '.bmp', '.gif']:
            self.logger.info("  📸 Extracting image metadata...")
            results['image_metadata'] = self._extract_image_metadata(target)
            if 'gps' in results.get('image_metadata', {}):
                gps = results['image_metadata']['gps']
                self.logger.warning(f"  📍 GPS Location found: {gps.get('latitude')}, {gps.get('longitude')}")
                self.logger.info(f"  🗺️  {gps.get('google_maps', 'N/A')}")

        elif ext == '.pdf':
            self.logger.info("  📄 Extracting PDF metadata...")
            results['pdf_metadata'] = self._extract_pdf_metadata(target)

        return results