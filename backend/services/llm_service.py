"""
LLM Service for AI-powered scam analysis.

Integrates with OpenAI GPT-4 and Anthropic Claude for advanced
text analysis, explanation generation, and threat classification.
"""

import logging
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from django.conf import settings

logger = logging.getLogger('scamlytic.services.llm')


@dataclass
class LLMAnalysisResult:
    """Result from LLM analysis."""
    is_scam: bool
    confidence: float
    threat_type: str
    explanation: str
    red_flags: List[str]
    recommended_action: str
    detailed_analysis: Dict[str, Any]


class LLMService:
    """
    Service for LLM-based scam analysis.

    Uses GPT-4 or Claude for:
    - Message content analysis
    - Social engineering detection
    - Explanation generation
    - Threat classification
    """

    SCAM_ANALYSIS_SYSTEM_PROMPT = """You are an expert scam detection analyst specializing in identifying fraudulent messages, phishing attempts, and social engineering attacks. You have extensive knowledge of:

1. Common scam patterns (advance fee fraud, lottery scams, romance scams, investment scams, etc.)
2. Phishing techniques and URL manipulation
3. Social engineering tactics (urgency, authority, scarcity, fear)
4. Regional scam patterns (especially Nigerian/West African 419 scams, BVN/NIN phishing)
5. Financial fraud indicators

Your task is to analyze messages and identify potential scams with high accuracy while minimizing false positives.

Analyze the following aspects:
- Urgency indicators (limited time, act now, expires soon)
- Authority claims (bank, government, tech support)
- Financial requests (wire transfers, gift cards, crypto)
- Personal information requests (SSN, bank details, passwords)
- Grammatical patterns common in scams
- Too-good-to-be-true promises
- Pressure tactics and emotional manipulation

Respond in JSON format only."""

    ANALYSIS_USER_TEMPLATE = """Analyze this message for scam indicators:

MESSAGE CONTENT:
\"\"\"
{content}
\"\"\"

CONTEXT: {context}
{additional_context}

Respond with a JSON object containing:
{{
    "is_scam": boolean,
    "confidence": float (0.0-1.0),
    "threat_type": string (one of: PHISHING_URL, BVN_PHISHING, NIN_PHISHING, BANK_IMPERSONATION, LOTTERY_SCAM, ADVANCE_FEE, ROMANCE_SCAM, JOB_SCAM, INVESTMENT_SCAM, CRYPTO_SCAM, IMPERSONATION, GOVERNMENT_SCAM, TECH_SUPPORT_SCAM, LIKELY_SAFE),
    "scam_score": integer (0-100),
    "red_flags": [list of specific indicators found],
    "explanation": "human-readable explanation of findings",
    "recommended_action": "what the user should do",
    "manipulation_tactics": [list of psychological tactics used],
    "key_phrases": [suspicious phrases identified],
    "legitimate_indicators": [any signs this might be legitimate]
}}"""

    def __init__(self):
        self.openai_client = None
        self.anthropic_client = None
        self._init_clients()

    def _init_clients(self):
        """Initialize LLM clients."""
        # Initialize OpenAI
        if settings.OPENAI_API_KEY:
            try:
                import openai
                self.openai_client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
                logger.info("OpenAI client initialized")
            except ImportError:
                logger.warning("OpenAI package not installed")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI: {e}")

        # Initialize Anthropic
        if settings.ANTHROPIC_API_KEY:
            try:
                import anthropic
                self.anthropic_client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
                logger.info("Anthropic client initialized")
            except ImportError:
                logger.warning("Anthropic package not installed")
            except Exception as e:
                logger.error(f"Failed to initialize Anthropic: {e}")

    def analyze_message(
        self,
        content: str,
        context: str = "unknown",
        additional_info: Optional[Dict[str, Any]] = None,
        prefer_provider: str = "auto"
    ) -> LLMAnalysisResult:
        """
        Analyze a message using LLM for scam detection.

        Args:
            content: The message content to analyze
            context: Context like 'whatsapp', 'sms', 'email', 'social'
            additional_info: Additional context (sender info, etc.)
            prefer_provider: 'openai', 'anthropic', or 'auto'

        Returns:
            LLMAnalysisResult with detailed analysis
        """
        # Build additional context string
        additional_context = ""
        if additional_info:
            if additional_info.get('sender_phone'):
                additional_context += f"\nSender phone: {additional_info['sender_phone']}"
            if additional_info.get('sender_email'):
                additional_context += f"\nSender email: {additional_info['sender_email']}"
            if additional_info.get('urls_found'):
                additional_context += f"\nURLs in message: {additional_info['urls_found']}"

        # Format user message
        user_message = self.ANALYSIS_USER_TEMPLATE.format(
            content=content[:4000],  # Limit content length
            context=context,
            additional_context=additional_context
        )

        # Try preferred provider first
        result = None
        if prefer_provider == "openai" or (prefer_provider == "auto" and self.openai_client):
            result = self._analyze_with_openai(user_message)
        elif prefer_provider == "anthropic" or (prefer_provider == "auto" and self.anthropic_client):
            result = self._analyze_with_anthropic(user_message)

        # Fallback to other provider
        if result is None:
            if self.anthropic_client and prefer_provider != "anthropic":
                result = self._analyze_with_anthropic(user_message)
            elif self.openai_client and prefer_provider != "openai":
                result = self._analyze_with_openai(user_message)

        # If still no result, return default
        if result is None:
            return self._get_fallback_analysis(content)

        return result

    def _analyze_with_openai(self, user_message: str) -> Optional[LLMAnalysisResult]:
        """Analyze using OpenAI GPT-4."""
        if not self.openai_client:
            return None

        try:
            response = self.openai_client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": self.SCAM_ANALYSIS_SYSTEM_PROMPT},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.1,
                max_tokens=1500,
                response_format={"type": "json_object"}
            )

            result_text = response.choices[0].message.content
            return self._parse_llm_response(result_text)

        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}")
            return None

    def _analyze_with_anthropic(self, user_message: str) -> Optional[LLMAnalysisResult]:
        """Analyze using Anthropic Claude."""
        if not self.anthropic_client:
            return None

        try:
            response = self.anthropic_client.messages.create(
                model=settings.ANTHROPIC_MODEL,
                max_tokens=1500,
                system=self.SCAM_ANALYSIS_SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": user_message}
                ]
            )

            result_text = response.content[0].text
            return self._parse_llm_response(result_text)

        except Exception as e:
            logger.error(f"Anthropic analysis failed: {e}")
            return None

    def _parse_llm_response(self, response_text: str) -> LLMAnalysisResult:
        """Parse LLM JSON response into result object."""
        try:
            # Try to extract JSON from response
            response_text = response_text.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]

            data = json.loads(response_text)

            return LLMAnalysisResult(
                is_scam=data.get('is_scam', False),
                confidence=float(data.get('confidence', 0.5)),
                threat_type=data.get('threat_type', 'LIKELY_SAFE'),
                explanation=data.get('explanation', ''),
                red_flags=data.get('red_flags', []),
                recommended_action=data.get('recommended_action', ''),
                detailed_analysis={
                    'scam_score': data.get('scam_score', 0),
                    'manipulation_tactics': data.get('manipulation_tactics', []),
                    'key_phrases': data.get('key_phrases', []),
                    'legitimate_indicators': data.get('legitimate_indicators', [])
                }
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return self._get_fallback_analysis("")

    def _get_fallback_analysis(self, content: str) -> LLMAnalysisResult:
        """Return fallback analysis when LLM is unavailable."""
        return LLMAnalysisResult(
            is_scam=False,
            confidence=0.0,
            threat_type='LIKELY_SAFE',
            explanation='LLM analysis unavailable. Analysis based on pattern matching only.',
            red_flags=[],
            recommended_action='Exercise caution and verify independently.',
            detailed_analysis={'fallback': True}
        )

    def generate_explanation(
        self,
        analysis_result: Dict[str, Any],
        audience: str = "general"
    ) -> str:
        """
        Generate a human-readable explanation of analysis results.

        Args:
            analysis_result: The analysis result dictionary
            audience: Target audience ('general', 'technical', 'brief')

        Returns:
            Human-readable explanation string
        """
        if audience == "brief":
            template = "In one sentence, summarize this scam analysis result: {result}"
        elif audience == "technical":
            template = "Provide a technical security analysis of these findings: {result}"
        else:
            template = """Explain these scam analysis results in simple terms that anyone can understand.
Be clear about the risks and what the person should do: {result}"""

        prompt = template.format(result=json.dumps(analysis_result, indent=2))

        if self.openai_client:
            try:
                response = self.openai_client.chat.completions.create(
                    model="gpt-4o-mini",  # Use cheaper model for explanations
                    messages=[
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7,
                    max_tokens=500
                )
                return response.choices[0].message.content
            except Exception as e:
                logger.error(f"Explanation generation failed: {e}")

        # Fallback explanation
        score = analysis_result.get('scam_score', 0)
        if score >= 75:
            return "This appears to be a high-risk scam attempt. Do not respond or click any links."
        elif score >= 50:
            return "This message shows several warning signs. Proceed with extreme caution."
        elif score >= 25:
            return "This message has some suspicious elements. Verify the sender independently."
        else:
            return "This message appears to be low risk, but always stay vigilant."

    def is_available(self) -> bool:
        """Check if any LLM provider is available."""
        return self.openai_client is not None or self.anthropic_client is not None

    def get_available_providers(self) -> List[str]:
        """Get list of available LLM providers."""
        providers = []
        if self.openai_client:
            providers.append('openai')
        if self.anthropic_client:
            providers.append('anthropic')
        return providers
