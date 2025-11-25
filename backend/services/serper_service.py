"""
Serper.dev Integration Service.

Provides reverse image search, web search, and profile lookup
capabilities for catfish detection and scam investigation.
"""

import logging
import hashlib
import base64
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, quote_plus

import requests
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger('scamlytic.services.serper')


class SerperService:
    """
    Serper.dev API integration for image and web search.

    Used for:
    - Reverse image search (find where images appear online)
    - Profile name search (find associated accounts)
    - Phone/email search (find linked identities)
    - Domain reputation search
    """

    BASE_URL = 'https://google.serper.dev'

    def __init__(self):
        self.api_key = getattr(settings, 'SERPER_API_KEY', None)
        self.timeout = 30
        self.cache_ttl = 3600  # 1 hour cache

    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers."""
        return {
            'X-API-KEY': self.api_key,
            'Content-Type': 'application/json',
        }

    def _cache_key(self, prefix: str, query: str) -> str:
        """Generate cache key."""
        query_hash = hashlib.md5(query.encode()).hexdigest()
        return f"serper:{prefix}:{query_hash}"

    def is_available(self) -> bool:
        """Check if Serper API is configured."""
        return bool(self.api_key)

    def reverse_image_search(
        self,
        image_url: Optional[str] = None,
        image_base64: Optional[str] = None,
        num_results: int = 20
    ) -> Dict[str, Any]:
        """
        Perform reverse image search using Google Images via Serper.

        Args:
            image_url: URL of the image to search
            image_base64: Base64 encoded image data
            num_results: Number of results to return

        Returns:
            Dict with matches, sources, and analysis
        """
        if not self.api_key:
            return {
                'success': False,
                'error': 'Serper API key not configured',
                'matches': [],
            }

        result = {
            'success': False,
            'matches': [],
            'total_matches': 0,
            'image_found_elsewhere': False,
            'is_stock_photo': False,
            'stock_photo_source': None,
            'social_profiles': [],
            'websites': [],
        }

        try:
            # Use Google Lens/Image search via Serper
            if image_url:
                # Check cache
                cache_key = self._cache_key('img', image_url)
                cached = cache.get(cache_key)
                if cached:
                    return cached

                # Perform reverse image search using Google Images
                search_url = f"{self.BASE_URL}/images"
                payload = {
                    'q': f'site:* inurl:{image_url}',
                    'num': num_results,
                }

                # Alternative: Use lens endpoint for actual reverse search
                lens_url = f"{self.BASE_URL}/lens"
                lens_payload = {
                    'url': image_url,
                    'num': num_results,
                }

                response = requests.post(
                    lens_url,
                    headers=self._get_headers(),
                    json=lens_payload,
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    data = response.json()
                    result['success'] = True

                    # Process visual matches
                    visual_matches = data.get('visual_matches', [])
                    for match in visual_matches:
                        match_info = {
                            'title': match.get('title', ''),
                            'link': match.get('link', ''),
                            'source': match.get('source', ''),
                            'thumbnail': match.get('thumbnail', ''),
                        }
                        result['matches'].append(match_info)

                        # Check for stock photo sites
                        link = match.get('link', '').lower()
                        if self._is_stock_photo_site(link):
                            result['is_stock_photo'] = True
                            result['stock_photo_source'] = self._extract_domain(link)

                        # Check for social media profiles
                        if self._is_social_profile(link):
                            result['social_profiles'].append({
                                'platform': self._get_social_platform(link),
                                'url': match.get('link'),
                                'title': match.get('title'),
                            })
                        else:
                            result['websites'].append({
                                'url': match.get('link'),
                                'title': match.get('title'),
                                'domain': self._extract_domain(link),
                            })

                    # Process knowledge graph if available
                    knowledge = data.get('knowledge', {})
                    if knowledge:
                        result['identified_entity'] = {
                            'title': knowledge.get('title'),
                            'description': knowledge.get('description'),
                            'type': knowledge.get('type'),
                        }

                    result['total_matches'] = len(result['matches'])
                    result['image_found_elsewhere'] = result['total_matches'] > 0

                    # Cache successful result
                    cache.set(cache_key, result, self.cache_ttl)

                else:
                    result['error'] = f"API error: {response.status_code}"
                    logger.error(f"Serper API error: {response.status_code} - {response.text}")

        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout'
            logger.error("Serper API timeout")
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Serper reverse image search error: {e}")

        return result

    def search_profile_name(
        self,
        name: str,
        additional_context: Optional[str] = None,
        num_results: int = 10
    ) -> Dict[str, Any]:
        """
        Search for a person's name to find associated profiles and information.

        Args:
            name: Person's name to search
            additional_context: Additional context (location, profession, etc.)
            num_results: Number of results

        Returns:
            Dict with profile matches and analysis
        """
        if not self.api_key:
            return {'success': False, 'error': 'API key not configured'}

        result = {
            'success': False,
            'profiles': [],
            'websites': [],
            'news_mentions': [],
            'consistency_score': 0.0,
        }

        try:
            # Build search query
            query = f'"{name}"'
            if additional_context:
                query += f' {additional_context}'

            # Check cache
            cache_key = self._cache_key('name', query)
            cached = cache.get(cache_key)
            if cached:
                return cached

            # Search web
            response = requests.post(
                f"{self.BASE_URL}/search",
                headers=self._get_headers(),
                json={
                    'q': query,
                    'num': num_results,
                },
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                result['success'] = True

                # Process organic results
                organic = data.get('organic', [])
                for item in organic:
                    link = item.get('link', '').lower()

                    if self._is_social_profile(link):
                        result['profiles'].append({
                            'platform': self._get_social_platform(link),
                            'url': item.get('link'),
                            'title': item.get('title'),
                            'snippet': item.get('snippet'),
                        })
                    else:
                        result['websites'].append({
                            'url': item.get('link'),
                            'title': item.get('title'),
                            'snippet': item.get('snippet'),
                            'domain': self._extract_domain(link),
                        })

                # Process news if available
                news = data.get('news', [])
                for item in news:
                    result['news_mentions'].append({
                        'title': item.get('title'),
                        'link': item.get('link'),
                        'source': item.get('source'),
                        'date': item.get('date'),
                    })

                # Calculate consistency score
                result['consistency_score'] = self._calculate_profile_consistency(
                    result['profiles']
                )

                cache.set(cache_key, result, self.cache_ttl)

            else:
                result['error'] = f"API error: {response.status_code}"

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Serper name search error: {e}")

        return result

    def search_phone_number(
        self,
        phone_number: str,
        num_results: int = 10
    ) -> Dict[str, Any]:
        """
        Search for phone number associations.

        Args:
            phone_number: Phone number to search
            num_results: Number of results

        Returns:
            Dict with phone number associations
        """
        if not self.api_key:
            return {'success': False, 'error': 'API key not configured'}

        result = {
            'success': False,
            'associated_names': [],
            'scam_reports': [],
            'business_listings': [],
            'risk_indicators': [],
        }

        try:
            # Normalize phone number for search
            clean_number = ''.join(filter(str.isdigit, phone_number))

            # Check cache
            cache_key = self._cache_key('phone', clean_number)
            cached = cache.get(cache_key)
            if cached:
                return cached

            # Search for phone number
            queries = [
                f'"{phone_number}"',
                f'"{clean_number}"',
                f'"{phone_number}" scam OR fraud OR spam',
            ]

            all_results = []
            for query in queries[:2]:  # Limit API calls
                response = requests.post(
                    f"{self.BASE_URL}/search",
                    headers=self._get_headers(),
                    json={'q': query, 'num': num_results},
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    data = response.json()
                    all_results.extend(data.get('organic', []))

            result['success'] = True

            # Analyze results
            scam_keywords = ['scam', 'fraud', 'spam', 'fake', 'report', 'complaint', 'warning']

            for item in all_results:
                title = item.get('title', '').lower()
                snippet = item.get('snippet', '').lower()
                link = item.get('link', '').lower()

                # Check for scam reports
                if any(kw in title or kw in snippet for kw in scam_keywords):
                    result['scam_reports'].append({
                        'source': item.get('link'),
                        'title': item.get('title'),
                        'snippet': item.get('snippet'),
                    })
                    result['risk_indicators'].append('scam_report_found')

                # Check for business listings
                if 'business' in link or 'yelp' in link or 'yellowpages' in link:
                    result['business_listings'].append({
                        'source': item.get('link'),
                        'title': item.get('title'),
                    })

            # Deduplicate risk indicators
            result['risk_indicators'] = list(set(result['risk_indicators']))

            cache.set(cache_key, result, self.cache_ttl)

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Serper phone search error: {e}")

        return result

    def search_email(
        self,
        email: str,
        num_results: int = 10
    ) -> Dict[str, Any]:
        """
        Search for email associations and exposure.

        Args:
            email: Email address to search
            num_results: Number of results

        Returns:
            Dict with email associations
        """
        if not self.api_key:
            return {'success': False, 'error': 'API key not configured'}

        result = {
            'success': False,
            'associated_profiles': [],
            'public_mentions': [],
            'risk_indicators': [],
        }

        try:
            cache_key = self._cache_key('email', email)
            cached = cache.get(cache_key)
            if cached:
                return cached

            response = requests.post(
                f"{self.BASE_URL}/search",
                headers=self._get_headers(),
                json={'q': f'"{email}"', 'num': num_results},
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                result['success'] = True

                for item in data.get('organic', []):
                    link = item.get('link', '').lower()

                    if self._is_social_profile(link):
                        result['associated_profiles'].append({
                            'platform': self._get_social_platform(link),
                            'url': item.get('link'),
                            'title': item.get('title'),
                        })
                    else:
                        result['public_mentions'].append({
                            'url': item.get('link'),
                            'title': item.get('title'),
                            'snippet': item.get('snippet'),
                        })

                # Check for data breach mentions
                breach_keywords = ['breach', 'leaked', 'exposed', 'pwned', 'hack']
                for item in data.get('organic', []):
                    text = f"{item.get('title', '')} {item.get('snippet', '')}".lower()
                    if any(kw in text for kw in breach_keywords):
                        result['risk_indicators'].append('potential_breach_exposure')
                        break

                cache.set(cache_key, result, self.cache_ttl)

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Serper email search error: {e}")

        return result

    def search_domain_reputation(
        self,
        domain: str,
        num_results: int = 10
    ) -> Dict[str, Any]:
        """
        Search for domain reputation and scam reports.

        Args:
            domain: Domain to search
            num_results: Number of results

        Returns:
            Dict with domain reputation info
        """
        if not self.api_key:
            return {'success': False, 'error': 'API key not configured'}

        result = {
            'success': False,
            'scam_reports': [],
            'reviews': [],
            'trust_indicators': [],
            'risk_indicators': [],
        }

        try:
            cache_key = self._cache_key('domain', domain)
            cached = cache.get(cache_key)
            if cached:
                return cached

            # Search for domain + scam/review mentions
            queries = [
                f'"{domain}" scam OR fraud OR fake',
                f'"{domain}" review OR legit OR trust',
            ]

            all_results = []
            for query in queries:
                response = requests.post(
                    f"{self.BASE_URL}/search",
                    headers=self._get_headers(),
                    json={'q': query, 'num': num_results // 2},
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    all_results.extend(response.json().get('organic', []))

            result['success'] = True

            scam_keywords = ['scam', 'fraud', 'fake', 'warning', 'beware', 'complaint']
            trust_keywords = ['legit', 'legitimate', 'trusted', 'reliable', 'safe']

            for item in all_results:
                text = f"{item.get('title', '')} {item.get('snippet', '')}".lower()

                if any(kw in text for kw in scam_keywords):
                    result['scam_reports'].append({
                        'source': item.get('link'),
                        'title': item.get('title'),
                        'snippet': item.get('snippet'),
                    })
                    result['risk_indicators'].append('scam_report_found')

                if any(kw in text for kw in trust_keywords):
                    if 'not legit' not in text and 'not trusted' not in text:
                        result['trust_indicators'].append({
                            'source': item.get('link'),
                            'title': item.get('title'),
                        })

            result['risk_indicators'] = list(set(result['risk_indicators']))
            cache.set(cache_key, result, self.cache_ttl)

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Serper domain search error: {e}")

        return result

    # Helper methods

    def _is_stock_photo_site(self, url: str) -> bool:
        """Check if URL is from a stock photo site."""
        stock_sites = [
            'shutterstock', 'gettyimages', 'istockphoto', 'adobe.com/stock',
            'depositphotos', 'dreamstime', '123rf', 'alamy', 'bigstockphoto',
            'unsplash', 'pexels', 'pixabay', 'freepik', 'stockphoto',
        ]
        return any(site in url.lower() for site in stock_sites)

    def _is_social_profile(self, url: str) -> bool:
        """Check if URL is a social media profile."""
        social_sites = [
            'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
            'linkedin.com', 'tiktok.com', 'youtube.com', 'pinterest.com',
            'snapchat.com', 'reddit.com/user', 'tumblr.com',
        ]
        return any(site in url.lower() for site in social_sites)

    def _get_social_platform(self, url: str) -> str:
        """Extract social media platform name from URL."""
        platforms = {
            'facebook.com': 'Facebook',
            'instagram.com': 'Instagram',
            'twitter.com': 'Twitter',
            'x.com': 'X (Twitter)',
            'linkedin.com': 'LinkedIn',
            'tiktok.com': 'TikTok',
            'youtube.com': 'YouTube',
            'pinterest.com': 'Pinterest',
            'snapchat.com': 'Snapchat',
            'reddit.com': 'Reddit',
            'tumblr.com': 'Tumblr',
        }
        url_lower = url.lower()
        for domain, name in platforms.items():
            if domain in url_lower:
                return name
        return 'Unknown'

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc or url
        except Exception:
            return url

    def _calculate_profile_consistency(
        self,
        profiles: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate consistency score for found profiles.

        Higher score = more consistent identity across platforms
        """
        if not profiles:
            return 0.0

        # Simple heuristic: more profiles = potentially more consistent
        # Real implementation would compare profile details
        base_score = min(len(profiles) * 0.2, 1.0)

        # Check for platform diversity
        platforms = set(p.get('platform') for p in profiles)
        diversity_bonus = min(len(platforms) * 0.1, 0.3)

        return min(base_score + diversity_bonus, 1.0)


class CatfishDetector:
    """
    High-level catfish detection using Serper and other services.
    """

    def __init__(self):
        self.serper = SerperService()

    def analyze_profile(
        self,
        name: Optional[str] = None,
        image_url: Optional[str] = None,
        profile_url: Optional[str] = None,
        claimed_location: Optional[str] = None,
        claimed_profession: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Comprehensive catfish analysis using multiple data points.

        Args:
            name: Claimed name
            image_url: Profile image URL
            profile_url: Social media profile URL
            claimed_location: Claimed location
            claimed_profession: Claimed profession

        Returns:
            Comprehensive catfish analysis result
        """
        result = {
            'is_likely_catfish': False,
            'confidence': 0.0,
            'risk_score': 0,
            'signals': [],
            'image_analysis': None,
            'name_search': None,
            'profile_consistency': 0.0,
            'red_flags': [],
            'recommendations': [],
        }

        # 1. Reverse image search
        if image_url and self.serper.is_available():
            img_result = self.serper.reverse_image_search(image_url)
            result['image_analysis'] = img_result

            if img_result.get('success'):
                if img_result.get('is_stock_photo'):
                    result['signals'].append('stock_photo_detected')
                    result['red_flags'].append(
                        f"Profile image found on stock photo site: {img_result.get('stock_photo_source')}"
                    )
                    result['risk_score'] += 40

                if img_result.get('total_matches', 0) > 5:
                    result['signals'].append('image_found_elsewhere')
                    result['red_flags'].append(
                        f"Profile image found on {img_result.get('total_matches')} other websites"
                    )
                    result['risk_score'] += 30

                # Check if image is associated with different names
                if img_result.get('social_profiles'):
                    other_profiles = img_result['social_profiles']
                    if name and other_profiles:
                        # Check for name mismatches
                        for profile in other_profiles:
                            if name.lower() not in profile.get('title', '').lower():
                                result['signals'].append('name_mismatch')
                                result['red_flags'].append(
                                    f"Image linked to different identity on {profile.get('platform')}"
                                )
                                result['risk_score'] += 25
                                break

        # 2. Name search
        if name and self.serper.is_available():
            context = f"{claimed_location or ''} {claimed_profession or ''}".strip()
            name_result = self.serper.search_profile_name(name, context or None)
            result['name_search'] = name_result

            if name_result.get('success'):
                result['profile_consistency'] = name_result.get('consistency_score', 0)

                # Low profile presence is suspicious
                if len(name_result.get('profiles', [])) == 0:
                    result['signals'].append('no_online_presence')
                    result['red_flags'].append(
                        "No verifiable online presence found for this name"
                    )
                    result['risk_score'] += 20

        # 3. Calculate final assessment
        if result['risk_score'] >= 60:
            result['is_likely_catfish'] = True
            result['confidence'] = min(result['risk_score'] / 100, 0.95)
            result['recommendations'] = [
                "Do not share personal or financial information",
                "Request a video call to verify identity",
                "Reverse search any additional images they share",
                "Be cautious of romantic advances or financial requests",
            ]
        elif result['risk_score'] >= 30:
            result['confidence'] = result['risk_score'] / 100
            result['recommendations'] = [
                "Proceed with caution",
                "Verify identity through video call",
                "Research their claimed details independently",
            ]
        else:
            result['confidence'] = 0.3
            result['recommendations'] = [
                "Profile appears legitimate but always exercise caution",
                "Standard online safety practices recommended",
            ]

        return result
