"""
Image Analyzer Service.

Comprehensive image analysis for catfish detection including
reverse image search, face detection, and AI generation detection.
"""

import logging
import hashlib
import time
import base64
import io
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

from django.conf import settings
from django.core.cache import cache

from algorithms.risk_scorer import RiskScorer
from .serper_service import SerperService, CatfishDetector

logger = logging.getLogger('scamlytic.services.image')


@dataclass
class ImageAnalysisResult:
    """Complete image analysis result."""
    request_id: str
    scam_score: int
    verdict: str
    threat_type: str
    explanation: str
    recommended_action: str
    signals: List[str]
    confidence: float

    # Image info
    image_hash: str = ''
    perceptual_hash: str = ''
    image_size: Tuple[int, int] = (0, 0)
    file_size_bytes: int = 0

    # Face detection
    has_face: bool = False
    face_count: int = 0
    face_locations: List[Dict[str, int]] = field(default_factory=list)

    # Reverse image search
    reverse_search_matches: List[Dict[str, Any]] = field(default_factory=list)
    image_found_elsewhere: bool = False
    match_count: int = 0

    # AI detection
    is_ai_generated: bool = False
    ai_detection_confidence: float = 0.0

    # Stock photo detection
    is_stock_photo: bool = False
    stock_photo_source: str = ''

    # Image quality
    quality_score: float = 0.0
    is_manipulated: bool = False

    # Detailed analysis
    analysis_details: Dict[str, Any] = field(default_factory=dict)

    processing_time_ms: int = 0


class ImageAnalyzerService:
    """
    Advanced image analysis service for catfish detection.

    Performs reverse image search, face detection, AI generation
    detection, and profile consistency analysis.
    """

    # Known stock photo domains
    STOCK_PHOTO_DOMAINS = [
        'shutterstock.com', 'gettyimages.com', 'istockphoto.com',
        'stock.adobe.com', 'depositphotos.com', 'dreamstime.com',
        '123rf.com', 'alamy.com', 'bigstockphoto.com', 'unsplash.com',
        'pexels.com', 'pixabay.com', 'freepik.com',
    ]

    def __init__(self):
        self.risk_scorer = RiskScorer()
        self.serper_service = SerperService()
        self.catfish_detector = CatfishDetector()
        self._init_services()

    def _init_services(self):
        """Initialize image processing services."""
        # Try to import PIL
        try:
            from PIL import Image
            self.Image = Image
            self._has_pil = True
        except ImportError:
            logger.warning("PIL not available")
            self._has_pil = False

        # Try to import imagehash
        try:
            import imagehash
            self.imagehash = imagehash
            self._has_imagehash = True
        except ImportError:
            logger.warning("imagehash not available")
            self._has_imagehash = False

    def analyze(
        self,
        image_data: Optional[bytes] = None,
        image_url: Optional[str] = None,
        image_base64: Optional[str] = None,
        profile_url: Optional[str] = None,
        deep_scan: bool = True,
        request_id: Optional[str] = None
    ) -> ImageAnalysisResult:
        """
        Perform comprehensive image analysis for catfish detection.

        Args:
            image_data: Raw image bytes
            image_url: URL of the image
            image_base64: Base64 encoded image
            profile_url: Social media profile URL
            deep_scan: Whether to perform reverse image search
            request_id: Optional request ID

        Returns:
            ImageAnalysisResult with complete analysis
        """
        start_time = time.time()

        # Generate request ID
        if not request_id:
            data_hash = hashlib.md5(
                (str(image_url) + str(profile_url)).encode()
            ).hexdigest()[:8]
            request_id = f"img_{data_hash}_{int(time.time())}"

        # Initialize result
        result = ImageAnalysisResult(
            request_id=request_id,
            scam_score=0,
            verdict='LOW_RISK',
            threat_type='LIKELY_SAFE',
            explanation='',
            recommended_action='',
            signals=[],
            confidence=0.5
        )

        try:
            # 1. Load image
            image = None
            if image_base64:
                image_data = base64.b64decode(image_base64)
            elif image_url:
                image_data = self._fetch_image(image_url)

            if image_data and self._has_pil:
                try:
                    image = self.Image.open(io.BytesIO(image_data))
                    result.image_size = image.size
                    result.file_size_bytes = len(image_data)
                except Exception as e:
                    logger.error(f"Failed to open image: {e}")

            # 2. Calculate image hashes
            if image_data:
                result.image_hash = hashlib.sha256(image_data).hexdigest()

            if image and self._has_imagehash:
                try:
                    result.perceptual_hash = str(self.imagehash.phash(image))
                except Exception as e:
                    logger.warning(f"Perceptual hash failed: {e}")

            # 3. Face detection
            if image:
                face_result = self._detect_faces(image)
                result.has_face = face_result['has_face']
                result.face_count = face_result['face_count']
                result.face_locations = face_result.get('locations', [])

            # 4. AI generation detection
            if image:
                ai_result = self._detect_ai_generated(image)
                result.is_ai_generated = ai_result['is_ai_generated']
                result.ai_detection_confidence = ai_result['confidence']

            # 5. Reverse image search (if deep scan)
            if deep_scan and (image_url or image_data):
                search_result = self._reverse_image_search(
                    image_url=image_url,
                    image_data=image_data
                )
                result.reverse_search_matches = search_result.get('matches', [])
                result.image_found_elsewhere = search_result.get('found_elsewhere', False)
                result.match_count = search_result.get('match_count', 0)
                result.is_stock_photo = search_result.get('is_stock_photo', False)
                result.stock_photo_source = search_result.get('stock_source', '')

            # 6. Profile analysis (if profile URL provided)
            if profile_url:
                profile_result = self._analyze_profile(profile_url)
                result.analysis_details['profile'] = profile_result

            # 7. Aggregate signals
            detected_signals = self._aggregate_signals(result)

            # 8. Calculate final risk score
            risk_assessment = self.risk_scorer.calculate_score(
                detected_signals,
                additional_data={
                    'ai_confidence': result.ai_detection_confidence,
                }
            )

            # 9. Determine threat type
            threat_type = self._determine_threat_type(result, detected_signals)

            # 10. Populate final result
            result.scam_score = risk_assessment.score
            result.verdict = risk_assessment.verdict
            result.threat_type = threat_type
            result.explanation = self._generate_explanation(result)
            result.recommended_action = risk_assessment.recommended_action
            result.signals = detected_signals
            result.confidence = risk_assessment.confidence

        except Exception as e:
            logger.error(f"Image analysis error: {e}")
            result.explanation = "Analysis encountered an error."
            result.recommended_action = "Exercise caution with this profile."

        # Calculate processing time
        result.processing_time_ms = int((time.time() - start_time) * 1000)

        return result

    def _fetch_image(self, url: str) -> Optional[bytes]:
        """Fetch image from URL."""
        try:
            import requests
            response = requests.get(
                url,
                timeout=30,
                headers={'User-Agent': 'Scamlytic/1.0'},
                stream=True
            )

            if response.status_code == 200:
                # Limit size to 10MB
                max_size = 10 * 1024 * 1024
                content = response.content
                if len(content) <= max_size:
                    return content

            return None

        except Exception as e:
            logger.error(f"Failed to fetch image: {e}")
            return None

    def _detect_faces(self, image) -> Dict[str, Any]:
        """Detect faces in image."""
        result = {
            'has_face': False,
            'face_count': 0,
            'locations': []
        }

        try:
            # Try OpenCV face detection
            import cv2
            import numpy as np

            # Convert PIL to OpenCV format
            img_array = np.array(image.convert('RGB'))
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)

            # Load face cascade
            face_cascade = cv2.CascadeClassifier(
                cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            )

            # Detect faces
            faces = face_cascade.detectMultiScale(
                gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
            )

            result['face_count'] = len(faces)
            result['has_face'] = len(faces) > 0
            result['locations'] = [
                {'x': int(x), 'y': int(y), 'width': int(w), 'height': int(h)}
                for (x, y, w, h) in faces
            ]

        except ImportError:
            logger.warning("OpenCV not available for face detection")
        except Exception as e:
            logger.error(f"Face detection failed: {e}")

        return result

    def _detect_ai_generated(self, image) -> Dict[str, Any]:
        """Detect if image is AI-generated."""
        result = {
            'is_ai_generated': False,
            'confidence': 0.0,
            'indicators': []
        }

        try:
            # Basic heuristics for AI detection
            # (Real implementation would use a trained model)

            indicators = []

            # Check for unnatural smoothness
            import numpy as np
            img_array = np.array(image.convert('RGB'))

            # Calculate local variance as a smoothness indicator
            from scipy import ndimage
            gray = np.mean(img_array, axis=2)
            local_var = ndimage.generic_filter(gray, np.var, size=3)
            mean_var = np.mean(local_var)

            if mean_var < 50:  # Very smooth
                indicators.append('unnatural_smoothness')

            # Check for repetitive patterns (common in AI images)
            # This is a simplified check

            # Check image metadata
            if hasattr(image, 'info'):
                info = image.info
                if 'Software' in info:
                    software = info['Software'].lower()
                    if any(ai in software for ai in ['midjourney', 'dalle', 'stable diffusion']):
                        indicators.append('ai_software_metadata')
                        result['is_ai_generated'] = True
                        result['confidence'] = 0.95

            if indicators:
                result['indicators'] = indicators
                if not result['is_ai_generated']:
                    result['confidence'] = len(indicators) * 0.3
                    result['is_ai_generated'] = result['confidence'] > 0.5

        except ImportError:
            logger.warning("Required libraries not available for AI detection")
        except Exception as e:
            logger.error(f"AI detection failed: {e}")

        return result

    def _reverse_image_search(
        self,
        image_url: Optional[str] = None,
        image_data: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Perform reverse image search using Serper.dev API.

        Uses Google Lens via Serper for comprehensive reverse image search.
        """
        result = {
            'matches': [],
            'found_elsewhere': False,
            'match_count': 0,
            'is_stock_photo': False,
            'stock_source': '',
            'social_profiles': [],
            'websites': [],
        }

        # Primary: Serper.dev reverse image search (Google Lens)
        if self.serper_service.is_available() and image_url:
            try:
                serper_result = self.serper_service.reverse_image_search(
                    image_url=image_url,
                    num_results=20
                )

                if serper_result.get('success'):
                    result['matches'] = serper_result.get('matches', [])
                    result['found_elsewhere'] = serper_result.get('image_found_elsewhere', False)
                    result['match_count'] = serper_result.get('total_matches', 0)
                    result['is_stock_photo'] = serper_result.get('is_stock_photo', False)
                    result['stock_source'] = serper_result.get('stock_photo_source', '')
                    result['social_profiles'] = serper_result.get('social_profiles', [])
                    result['websites'] = serper_result.get('websites', [])

                    # Add identified entity if found
                    if serper_result.get('identified_entity'):
                        result['identified_entity'] = serper_result['identified_entity']

                    logger.info(f"Serper reverse image search found {result['match_count']} matches")

            except Exception as e:
                logger.error(f"Serper reverse image search failed: {e}")

        # Fallback: TinEye API integration
        if not result['matches'] and getattr(settings, 'TINEYE_API_KEY', None):
            try:
                tineye_result = self._tineye_search(image_url, image_data)
                if tineye_result:
                    result['matches'].extend(tineye_result.get('matches', []))
                    result['match_count'] = len(result['matches'])
                    result['found_elsewhere'] = result['match_count'] > 0
            except Exception as e:
                logger.error(f"TinEye search failed: {e}")

        # Fallback: Google Cloud Vision API
        if not result['matches'] and getattr(settings, 'GOOGLE_CLOUD_VISION_KEY', None):
            try:
                vision_result = self._google_vision_search(image_url, image_data)
                if vision_result:
                    result['matches'].extend(vision_result.get('matches', []))
                    result['match_count'] = len(result['matches'])
                    result['found_elsewhere'] = result['match_count'] > 0
            except Exception as e:
                logger.error(f"Google Vision search failed: {e}")

        # Check for stock photo indicators in URL (fallback check)
        if image_url and not result['is_stock_photo']:
            for domain in self.STOCK_PHOTO_DOMAINS:
                if domain in image_url.lower():
                    result['is_stock_photo'] = True
                    result['stock_source'] = domain
                    result['found_elsewhere'] = True
                    break

        return result

    def _tineye_search(
        self,
        image_url: Optional[str] = None,
        image_data: Optional[bytes] = None
    ) -> Optional[Dict[str, Any]]:
        """TinEye API reverse image search."""
        try:
            import requests

            api_key = getattr(settings, 'TINEYE_API_KEY', None)
            if not api_key:
                return None

            url = 'https://api.tineye.com/rest/search/'
            headers = {'X-Api-Key': api_key}

            if image_url:
                response = requests.post(
                    url,
                    headers=headers,
                    data={'url': image_url},
                    timeout=30
                )
            elif image_data:
                response = requests.post(
                    url,
                    headers=headers,
                    files={'image': ('image.jpg', image_data)},
                    timeout=30
                )
            else:
                return None

            if response.status_code == 200:
                data = response.json()
                matches = data.get('results', {}).get('matches', [])
                return {
                    'matches': [
                        {
                            'url': m.get('backlinks', [{}])[0].get('url', ''),
                            'domain': m.get('domain', ''),
                        }
                        for m in matches[:20]
                    ]
                }

        except Exception as e:
            logger.error(f"TinEye API error: {e}")

        return None

    def _google_vision_search(
        self,
        image_url: Optional[str] = None,
        image_data: Optional[bytes] = None
    ) -> Optional[Dict[str, Any]]:
        """Google Cloud Vision API web detection."""
        try:
            from google.cloud import vision

            client = vision.ImageAnnotatorClient()

            if image_url:
                image = vision.Image()
                image.source.image_uri = image_url
            elif image_data:
                image = vision.Image(content=image_data)
            else:
                return None

            response = client.web_detection(image=image)
            web = response.web_detection

            matches = []

            # Full matching images
            for match in web.full_matching_images[:10]:
                matches.append({
                    'url': match.url,
                    'type': 'full_match',
                })

            # Partial matching images
            for match in web.partial_matching_images[:10]:
                matches.append({
                    'url': match.url,
                    'type': 'partial_match',
                })

            # Pages with matching images
            for page in web.pages_with_matching_images[:10]:
                matches.append({
                    'url': page.url,
                    'title': page.page_title,
                    'type': 'page_match',
                })

            return {'matches': matches}

        except ImportError:
            logger.warning("Google Cloud Vision library not installed")
        except Exception as e:
            logger.error(f"Google Vision API error: {e}")

        return None

    def _analyze_profile(self, profile_url: str) -> Dict[str, Any]:
        """Analyze social media profile."""
        result = {
            'platform': '',
            'username': '',
            'is_accessible': False,
            'indicators': []
        }

        # Detect platform
        if 'instagram.com' in profile_url:
            result['platform'] = 'instagram'
        elif 'facebook.com' in profile_url:
            result['platform'] = 'facebook'
        elif 'twitter.com' in profile_url or 'x.com' in profile_url:
            result['platform'] = 'twitter'
        elif 'linkedin.com' in profile_url:
            result['platform'] = 'linkedin'
        elif 'tiktok.com' in profile_url:
            result['platform'] = 'tiktok'

        # Extract username from URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(profile_url)
            path_parts = parsed.path.strip('/').split('/')
            if path_parts:
                result['username'] = path_parts[0]
        except Exception:
            pass

        return result

    def _aggregate_signals(self, result: ImageAnalysisResult) -> List[str]:
        """Aggregate all detected signals."""
        signals = set()

        # Image found elsewhere
        if result.image_found_elsewhere:
            signals.add('image_found_elsewhere')

        # Stock photo
        if result.is_stock_photo:
            signals.add('stock_photo_detected')

        # AI generated
        if result.is_ai_generated:
            if result.ai_detection_confidence > 0.8:
                signals.add('ai_generated_image')
            else:
                signals.add('possible_ai_image')

        # No face in profile photo
        if not result.has_face and result.file_size_bytes > 0:
            signals.add('no_face_detected')

        # Multiple faces (unusual for profile)
        if result.face_count > 1:
            signals.add('multiple_faces')

        # High match count
        if result.match_count > 10:
            signals.add('many_matches_found')

        # Profile indicators
        profile = result.analysis_details.get('profile', {})
        if profile.get('indicators'):
            for indicator in profile['indicators']:
                signals.add(indicator)

        # No significant issues
        if not signals:
            signals.add('no_blocklist_match')

        return list(signals)

    def _determine_threat_type(
        self,
        result: ImageAnalysisResult,
        signals: List[str]
    ) -> str:
        """Determine the primary threat type."""
        if 'image_found_elsewhere' in signals or 'many_matches_found' in signals:
            return 'CATFISH'
        if 'ai_generated_image' in signals:
            return 'CATFISH'
        if 'stock_photo_detected' in signals:
            return 'CATFISH'
        return 'LIKELY_SAFE'

    def _generate_explanation(self, result: ImageAnalysisResult) -> str:
        """Generate human-readable explanation."""
        explanations = []

        if result.is_ai_generated:
            explanations.append(
                f"This image appears to be AI-generated "
                f"(confidence: {result.ai_detection_confidence:.0%})."
            )

        if result.is_stock_photo:
            explanations.append(
                f"This image was found on stock photo site: {result.stock_photo_source}."
            )

        if result.image_found_elsewhere:
            explanations.append(
                f"This image was found on {result.match_count} other websites."
            )

        if not result.has_face and result.file_size_bytes > 0:
            explanations.append(
                "No human face was detected in this image."
            )

        if not explanations:
            if result.has_face:
                explanations.append(
                    "No significant issues detected with this image. "
                    "It appears to be a genuine photo."
                )
            else:
                explanations.append(
                    "Limited analysis available. Exercise normal caution."
                )

        return " ".join(explanations)

    def quick_scan(
        self,
        image_url: Optional[str] = None,
        image_base64: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Quick scan without deep reverse image search.
        """
        result = self.analyze(
            image_url=image_url,
            image_base64=image_base64,
            deep_scan=False
        )
        return {
            'scam_score': result.scam_score,
            'verdict': result.verdict,
            'has_face': result.has_face,
            'is_ai_generated': result.is_ai_generated,
            'signals': result.signals[:5],
            'processing_time_ms': result.processing_time_ms,
        }
