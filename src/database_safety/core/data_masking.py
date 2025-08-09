#!/usr/bin/env python3
"""
Advanced Data Masking and Anonymization Engine
Provides comprehensive PII detection and masking with format preservation.
"""

import hashlib
import logging
import random
import re
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import faker
import numpy as np
from faker.providers import BaseProvider


class MaskingLevel(str, Enum):
    """Data masking security levels."""
    NONE = "none"               # No masking
    BASIC = "basic"             # Simple masking 
    STANDARD = "standard"       # Comprehensive masking
    STRICT = "strict"           # Maximum security masking
    CUSTOM = "custom"           # Custom masking rules


class DataCategory(str, Enum):
    """Categories of sensitive data."""
    PII = "pii"                 # Personally Identifiable Information
    FINANCIAL = "financial"     # Financial data
    HEALTH = "health"          # Health information
    LOCATION = "location"      # Geographic data
    AUTHENTICATION = "auth"    # Passwords, tokens
    BUSINESS = "business"      # Business-sensitive data
    TECHNICAL = "technical"    # System information


@dataclass
class MaskingRule:
    """Individual data masking rule."""
    name: str
    category: DataCategory
    patterns: List[str]         # Column name patterns
    data_types: List[str]       # Applicable data types
    masking_strategy: str       # Strategy name
    preserve_format: bool = True
    preserve_length: bool = True
    preserve_null: bool = True
    confidence_threshold: float = 0.8
    enabled: bool = True
    
    def matches_column(self, column_name: str, data_type: str) -> float:
        """Check if rule matches column and return confidence score."""
        if not self.enabled:
            return 0.0
        
        column_lower = column_name.lower()
        confidence = 0.0
        
        # Check pattern matches
        pattern_matches = 0
        for pattern in self.patterns:
            if re.search(pattern.lower(), column_lower):
                pattern_matches += 1
        
        if pattern_matches > 0:
            confidence += (pattern_matches / len(self.patterns)) * 0.7
        
        # Check data type compatibility
        if data_type.lower() in [dt.lower() for dt in self.data_types]:
            confidence += 0.3
        
        return min(confidence, 1.0)


@dataclass
class MaskingResult:
    """Result of masking operation."""
    original_value: Any
    masked_value: Any
    rule_applied: Optional[MaskingRule] = None
    confidence: float = 0.0
    preserved_format: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class CustomFakerProvider(BaseProvider):
    """Custom Faker provider for specialized data generation."""
    
    def business_id(self) -> str:
        """Generate business ID."""
        return f"BIZ{random.randint(100000, 999999)}"
    
    def account_number(self) -> str:
        """Generate account number."""
        return f"ACC{random.randint(1000000000, 9999999999)}"
    
    def transaction_id(self) -> str:
        """Generate transaction ID."""
        return f"TXN{random.randint(100000000, 999999999)}"
    
    def api_key(self) -> str:
        """Generate API key."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    def database_hash(self) -> str:
        """Generate database hash."""
        return hashlib.sha256(self.generator.random.getrandbits(256).to_bytes(32, 'big')).hexdigest()


class DataMaskingEngine:
    """
    Advanced data masking engine with intelligent PII detection.
    
    Features:
    - Multi-level masking strategies
    - Format preservation
    - Custom masking rules
    - Statistical anonymization
    - Reversible masking (with key)
    - Performance optimization
    """
    
    def __init__(self, masking_level: MaskingLevel = MaskingLevel.STANDARD):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.masking_level = masking_level
        
        # Initialize Faker with custom provider
        self.fake = faker.Faker()
        self.fake.add_provider(CustomFakerProvider)
        
        # Masking rules
        self.masking_rules = self._create_default_rules()
        self.custom_rules: List[MaskingRule] = []
        
        # Performance caching
        self._rule_cache: Dict[str, List[MaskingRule]] = {}
        self._masked_values_cache: Dict[str, Any] = {}
        
        # Statistics
        self.masking_stats = {
            'total_values_processed': 0,
            'values_masked': 0,
            'values_preserved': 0,
            'cache_hits': 0,
            'processing_time': 0.0
        }
    
    def _create_default_rules(self) -> List[MaskingRule]:
        """Create comprehensive set of default masking rules."""
        return [
            # PII Rules
            MaskingRule(
                name="email_addresses",
                category=DataCategory.PII,
                patterns=[r"email", r"e_?mail", r"mail_?address", r"contact_?email"],
                data_types=["string", "varchar", "text"],
                masking_strategy="fake_email"
            ),
            MaskingRule(
                name="full_names",
                category=DataCategory.PII,
                patterns=[r"^name$", r"full_?name", r"display_?name", r"user_?name"],
                data_types=["string", "varchar", "text"],
                masking_strategy="fake_name"
            ),
            MaskingRule(
                name="first_names",
                category=DataCategory.PII,
                patterns=[r"first_?name", r"given_?name", r"fname"],
                data_types=["string", "varchar", "text"],
                masking_strategy="fake_first_name"
            ),
            MaskingRule(
                name="last_names",
                category=DataCategory.PII,
                patterns=[r"last_?name", r"family_?name", r"surname", r"lname"],
                data_types=["string", "varchar", "text"],
                masking_strategy="fake_last_name"
            ),
            MaskingRule(
                name="phone_numbers",
                category=DataCategory.PII,
                patterns=[r"phone", r"telephone", r"mobile", r"cell", r"contact_?number"],
                data_types=["string", "varchar"],
                masking_strategy="fake_phone"
            ),
            MaskingRule(
                name="ssn",
                category=DataCategory.PII,
                patterns=[r"ssn", r"social_?security", r"tax_?id"],
                data_types=["string", "varchar"],
                masking_strategy="fake_ssn"
            ),
            
            # Address Information
            MaskingRule(
                name="addresses",
                category=DataCategory.PII,
                patterns=[r"address", r"street", r"location"],
                data_types=["string", "varchar", "text"],
                masking_strategy="fake_address"
            ),
            MaskingRule(
                name="cities",
                category=DataCategory.LOCATION,
                patterns=[r"city", r"town", r"municipality"],
                data_types=["string", "varchar"],
                masking_strategy="fake_city"
            ),
            MaskingRule(
                name="states",
                category=DataCategory.LOCATION,
                patterns=[r"state", r"province", r"region"],
                data_types=["string", "varchar"],
                masking_strategy="fake_state"
            ),
            MaskingRule(
                name="zip_codes",
                category=DataCategory.LOCATION,
                patterns=[r"zip", r"postal", r"postcode"],
                data_types=["string", "varchar", "int"],
                masking_strategy="fake_zipcode"
            ),
            
            # Financial Information
            MaskingRule(
                name="credit_cards",
                category=DataCategory.FINANCIAL,
                patterns=[r"credit_?card", r"cc_?number", r"card_?number", r"payment_?card"],
                data_types=["string", "varchar"],
                masking_strategy="fake_credit_card"
            ),
            MaskingRule(
                name="bank_accounts",
                category=DataCategory.FINANCIAL,
                patterns=[r"account_?number", r"bank_?account", r"routing", r"iban"],
                data_types=["string", "varchar"],
                masking_strategy="fake_account_number"
            ),
            MaskingRule(
                name="salaries",
                category=DataCategory.FINANCIAL,
                patterns=[r"salary", r"wage", r"income", r"compensation", r"pay"],
                data_types=["decimal", "float", "money", "numeric"],
                masking_strategy="randomize_amount"
            ),
            
            # Authentication & Security
            MaskingRule(
                name="passwords",
                category=DataCategory.AUTHENTICATION,
                patterns=[r"password", r"pwd", r"pass", r"secret"],
                data_types=["string", "varchar", "text"],
                masking_strategy="fake_hash"
            ),
            MaskingRule(
                name="tokens",
                category=DataCategory.AUTHENTICATION,
                patterns=[r"token", r"key", r"secret", r"hash"],
                data_types=["string", "varchar", "text"],
                masking_strategy="fake_api_key"
            ),
            
            # Health Information
            MaskingRule(
                name="medical_ids",
                category=DataCategory.HEALTH,
                patterns=[r"patient_?id", r"medical_?record", r"mrn", r"health_?id"],
                data_types=["string", "varchar"],
                masking_strategy="fake_medical_id"
            ),
            
            # IP Addresses
            MaskingRule(
                name="ip_addresses",
                category=DataCategory.TECHNICAL,
                patterns=[r"ip_?address", r"remote_?addr", r"client_?ip"],
                data_types=["string", "varchar"],
                masking_strategy="fake_ipv4"
            ),
            
            # Business Data
            MaskingRule(
                name="company_names",
                category=DataCategory.BUSINESS,
                patterns=[r"company", r"business", r"organization", r"employer"],
                data_types=["string", "varchar", "text"],
                masking_strategy="fake_company"
            )
        ]
    
    def add_custom_rule(self, rule: MaskingRule) -> None:
        """Add custom masking rule."""
        self.custom_rules.append(rule)
        self._rule_cache.clear()  # Clear cache when rules change
        self.logger.info(f"Added custom masking rule: {rule.name}")
    
    def mask_value(
        self, 
        value: Any, 
        column_name: str, 
        data_type: str,
        table_name: Optional[str] = None
    ) -> MaskingResult:
        """
        Mask individual value based on column characteristics.
        
        Args:
            value: Original value to mask
            column_name: Name of the database column
            data_type: Data type of the column
            table_name: Optional table name for context
            
        Returns:
            MaskingResult with original and masked values
        """
        if value is None:
            return MaskingResult(
                original_value=None,
                masked_value=None,
                preserved_format=True
            )
        
        # Check cache first
        cache_key = f"{column_name}:{data_type}:{hash(str(value))}"
        if cache_key in self._masked_values_cache:
            self.masking_stats['cache_hits'] += 1
            cached_result = self._masked_values_cache[cache_key]
            return MaskingResult(
                original_value=value,
                masked_value=cached_result['masked_value'],
                rule_applied=cached_result['rule'],
                confidence=cached_result['confidence'],
                preserved_format=cached_result['preserved_format']
            )
        
        # Find applicable rules
        applicable_rules = self._get_applicable_rules(column_name, data_type)
        
        if not applicable_rules:
            # No masking rules apply - return original value
            result = MaskingResult(
                original_value=value,
                masked_value=value,
                preserved_format=True
            )
        else:
            # Apply best matching rule
            best_rule = max(applicable_rules, key=lambda r: r.matches_column(column_name, data_type))
            confidence = best_rule.matches_column(column_name, data_type)
            
            if confidence >= best_rule.confidence_threshold:
                masked_value = self._apply_masking_strategy(
                    value, 
                    best_rule.masking_strategy, 
                    best_rule
                )
                
                result = MaskingResult(
                    original_value=value,
                    masked_value=masked_value,
                    rule_applied=best_rule,
                    confidence=confidence,
                    preserved_format=best_rule.preserve_format
                )
            else:
                # Confidence too low - return original
                result = MaskingResult(
                    original_value=value,
                    masked_value=value,
                    preserved_format=True
                )
        
        # Update cache
        self._masked_values_cache[cache_key] = {
            'masked_value': result.masked_value,
            'rule': result.rule_applied,
            'confidence': result.confidence,
            'preserved_format': result.preserved_format
        }
        
        # Update statistics
        self.masking_stats['total_values_processed'] += 1
        if result.masked_value != result.original_value:
            self.masking_stats['values_masked'] += 1
        else:
            self.masking_stats['values_preserved'] += 1
        
        return result
    
    def _get_applicable_rules(self, column_name: str, data_type: str) -> List[MaskingRule]:
        """Get rules applicable to column."""
        cache_key = f"{column_name}:{data_type}"
        
        if cache_key in self._rule_cache:
            return self._rule_cache[cache_key]
        
        applicable_rules = []
        all_rules = self.masking_rules + self.custom_rules
        
        for rule in all_rules:
            if rule.enabled and rule.matches_column(column_name, data_type) > 0:
                applicable_rules.append(rule)
        
        self._rule_cache[cache_key] = applicable_rules
        return applicable_rules
    
    def _apply_masking_strategy(
        self, 
        value: Any, 
        strategy: str, 
        rule: MaskingRule
    ) -> Any:
        """Apply specific masking strategy to value."""
        
        try:
            if strategy == "fake_email":
                return self.fake.email()
            
            elif strategy == "fake_name":
                return self.fake.name()
            
            elif strategy == "fake_first_name":
                return self.fake.first_name()
            
            elif strategy == "fake_last_name":
                return self.fake.last_name()
            
            elif strategy == "fake_phone":
                if rule.preserve_format and isinstance(value, str):
                    # Preserve phone number format
                    return self._preserve_phone_format(value)
                return self.fake.phone_number()
            
            elif strategy == "fake_ssn":
                return self.fake.ssn()
            
            elif strategy == "fake_address":
                return self.fake.address()
            
            elif strategy == "fake_city":
                return self.fake.city()
            
            elif strategy == "fake_state":
                return self.fake.state()
            
            elif strategy == "fake_zipcode":
                if isinstance(value, int):
                    return random.randint(10000, 99999)
                return self.fake.zipcode()
            
            elif strategy == "fake_credit_card":
                if rule.preserve_format and isinstance(value, str):
                    return self._preserve_credit_card_format(value)
                return self.fake.credit_card_number()
            
            elif strategy == "fake_account_number":
                return self.fake.account_number()
            
            elif strategy == "randomize_amount":
                if isinstance(value, (int, float)):
                    return self._randomize_numeric_amount(value)
                return value
            
            elif strategy == "fake_hash":
                return self.fake.database_hash()
            
            elif strategy == "fake_api_key":
                return self.fake.api_key()
            
            elif strategy == "fake_medical_id":
                return f"MRN{random.randint(1000000, 9999999)}"
            
            elif strategy == "fake_ipv4":
                return self.fake.ipv4()
            
            elif strategy == "fake_company":
                return self.fake.company()
            
            elif strategy == "partial_mask":
                return self._partial_mask_string(str(value), rule.preserve_length)
            
            elif strategy == "shuffle_chars":
                return self._shuffle_string_chars(str(value))
            
            elif strategy == "replace_digits":
                return self._replace_digits(str(value))
            
            else:
                self.logger.warning(f"Unknown masking strategy: {strategy}")
                return self._partial_mask_string(str(value), rule.preserve_length)
                
        except Exception as e:
            self.logger.error(f"Error applying masking strategy {strategy}: {e}")
            return self._partial_mask_string(str(value), rule.preserve_length)
    
    def _preserve_phone_format(self, phone: str) -> str:
        """Preserve phone number format while masking digits."""
        if not isinstance(phone, str):
            return self.fake.phone_number()
        
        # Extract format pattern
        digits_only = re.sub(r'\D', '', phone)
        if len(digits_only) < 10:
            return self.fake.phone_number()
        
        # Generate new digits maintaining same count
        new_digits = ''.join([str(random.randint(0, 9)) for _ in range(len(digits_only))])
        
        # Apply format back
        result = phone
        digit_index = 0
        for i, char in enumerate(phone):
            if char.isdigit() and digit_index < len(new_digits):
                result = result[:i] + new_digits[digit_index] + result[i+1:]
                digit_index += 1
        
        return result
    
    def _preserve_credit_card_format(self, cc_number: str) -> str:
        """Preserve credit card format while masking digits."""
        if not isinstance(cc_number, str):
            return self.fake.credit_card_number()
        
        # Extract digits
        digits_only = re.sub(r'\D', '', cc_number)
        if len(digits_only) < 13:  # Minimum valid CC length
            return self.fake.credit_card_number()
        
        # Generate new number with same length
        new_cc = self.fake.credit_card_number().replace('-', '').replace(' ', '')
        new_cc = new_cc[:len(digits_only)]  # Match original length
        
        # Apply original format
        result = cc_number
        digit_index = 0
        for i, char in enumerate(cc_number):
            if char.isdigit() and digit_index < len(new_cc):
                result = result[:i] + new_cc[digit_index] + result[i+1:]
                digit_index += 1
        
        return result
    
    def _randomize_numeric_amount(self, amount: Union[int, float]) -> Union[int, float]:
        """Randomize numeric amount while preserving magnitude."""
        if amount == 0:
            return 0
        
        # Calculate order of magnitude
        magnitude = abs(amount)
        order = len(str(int(magnitude))) - 1
        
        # Generate random amount in same order of magnitude
        min_val = 10 ** order
        max_val = (10 ** (order + 1)) - 1
        
        if isinstance(amount, int):
            new_amount = random.randint(min_val, max_val)
        else:
            new_amount = random.uniform(min_val, max_val)
            # Preserve decimal places
            decimal_places = len(str(amount).split('.')[-1]) if '.' in str(amount) else 0
            new_amount = round(new_amount, decimal_places)
        
        # Preserve sign
        return new_amount if amount >= 0 else -new_amount
    
    def _partial_mask_string(self, value: str, preserve_length: bool = True) -> str:
        """Apply partial masking to string value."""
        if len(value) <= 2:
            return 'X' * len(value) if preserve_length else 'XX'
        
        if len(value) <= 4:
            return value[0] + 'X' * (len(value) - 2) + value[-1]
        
        # Show first 2 and last 2 characters
        visible_chars = 4
        masked_length = len(value) - visible_chars
        
        if preserve_length:
            return value[:2] + 'X' * masked_length + value[-2:]
        else:
            return value[:2] + 'XXX' + value[-2:]
    
    def _shuffle_string_chars(self, value: str) -> str:
        """Shuffle characters in string while preserving length."""
        chars = list(value)
        random.shuffle(chars)
        return ''.join(chars)
    
    def _replace_digits(self, value: str) -> str:
        """Replace all digits with random digits."""
        result = ""
        for char in value:
            if char.isdigit():
                result += str(random.randint(0, 9))
            else:
                result += char
        return result
    
    def mask_row_data(
        self, 
        row_data: Dict[str, Any], 
        column_definitions: Dict[str, str],
        table_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Mask all sensitive data in a row.
        
        Args:
            row_data: Dictionary of column values
            column_definitions: Column name to data type mapping
            table_name: Optional table name for context
            
        Returns:
            Dictionary with masked values
        """
        masked_row = {}
        
        for column_name, value in row_data.items():
            data_type = column_definitions.get(column_name, "string")
            
            result = self.mask_value(value, column_name, data_type, table_name)
            masked_row[column_name] = result.masked_value
        
        return masked_row
    
    def analyze_column_sensitivity(
        self, 
        column_name: str, 
        data_type: str,
        sample_values: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze column for sensitivity and provide masking recommendations.
        
        Args:
            column_name: Name of the column
            data_type: Data type of the column
            sample_values: Sample values for analysis
            
        Returns:
            Analysis results with masking recommendations
        """
        applicable_rules = self._get_applicable_rules(column_name, data_type)
        
        analysis = {
            'column_name': column_name,
            'data_type': data_type,
            'is_sensitive': len(applicable_rules) > 0,
            'sensitivity_score': 0.0,
            'recommended_strategy': None,
            'applicable_rules': [],
            'data_categories': [],
            'sample_analysis': {}
        }
        
        if applicable_rules:
            # Calculate overall sensitivity score
            scores = [rule.matches_column(column_name, data_type) for rule in applicable_rules]
            analysis['sensitivity_score'] = max(scores)
            
            # Get best rule
            best_rule = max(applicable_rules, key=lambda r: r.matches_column(column_name, data_type))
            analysis['recommended_strategy'] = best_rule.masking_strategy
            
            # Extract rule information
            for rule in applicable_rules:
                confidence = rule.matches_column(column_name, data_type)
                analysis['applicable_rules'].append({
                    'name': rule.name,
                    'category': rule.category.value,
                    'confidence': confidence,
                    'strategy': rule.masking_strategy
                })
                
                if rule.category.value not in analysis['data_categories']:
                    analysis['data_categories'].append(rule.category.value)
        
        # Analyze sample values if provided
        if sample_values:
            analysis['sample_analysis'] = self._analyze_sample_values(
                sample_values, column_name, data_type
            )
        
        return analysis
    
    def _analyze_sample_values(
        self, 
        values: List[Any], 
        column_name: str, 
        data_type: str
    ) -> Dict[str, Any]:
        """Analyze sample values for additional insights."""
        
        analysis = {
            'total_values': len(values),
            'null_count': sum(1 for v in values if v is None),
            'unique_count': len(set(str(v) for v in values if v is not None)),
            'patterns': [],
            'format_consistency': 0.0
        }
        
        non_null_values = [v for v in values if v is not None]
        if not non_null_values:
            return analysis
        
        # Detect common patterns
        string_values = [str(v) for v in non_null_values]
        
        # Email pattern
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        email_matches = sum(1 for v in string_values if email_pattern.match(v))
        if email_matches > 0:
            analysis['patterns'].append({
                'pattern': 'email',
                'matches': email_matches,
                'percentage': email_matches / len(string_values)
            })
        
        # Phone pattern
        phone_pattern = re.compile(r'^[\+]?[1-9][\d]{0,15}$|^\(\d{3}\)\s?\d{3}-?\d{4}$')
        phone_matches = sum(1 for v in string_values if re.sub(r'[\s\-\(\)]', '', v).isdigit() and len(re.sub(r'[\s\-\(\)]', '', v)) >= 10)
        if phone_matches > 0:
            analysis['patterns'].append({
                'pattern': 'phone',
                'matches': phone_matches,
                'percentage': phone_matches / len(string_values)
            })
        
        # Calculate format consistency
        if len(string_values) > 1:
            lengths = [len(v) for v in string_values]
            length_consistency = 1.0 - (np.std(lengths) / np.mean(lengths)) if np.mean(lengths) > 0 else 0
            analysis['format_consistency'] = max(0, min(1, length_consistency))
        
        return analysis
    
    def get_masking_statistics(self) -> Dict[str, Any]:
        """Get comprehensive masking statistics."""
        stats = self.masking_stats.copy()
        
        if stats['total_values_processed'] > 0:
            stats['masking_rate'] = stats['values_masked'] / stats['total_values_processed']
            stats['preservation_rate'] = stats['values_preserved'] / stats['total_values_processed']
            stats['cache_hit_rate'] = stats['cache_hits'] / stats['total_values_processed']
        
        stats['rules_loaded'] = len(self.masking_rules) + len(self.custom_rules)
        stats['cache_size'] = len(self._masked_values_cache)
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset masking statistics."""
        self.masking_stats = {
            'total_values_processed': 0,
            'values_masked': 0,
            'values_preserved': 0,
            'cache_hits': 0,
            'processing_time': 0.0
        }
    
    def clear_cache(self) -> None:
        """Clear internal caches."""
        self._rule_cache.clear()
        self._masked_values_cache.clear()
        self.logger.info("Cleared masking caches")


# Utility functions for common masking operations
def create_masking_engine(level: MaskingLevel = MaskingLevel.STANDARD) -> DataMaskingEngine:
    """Create pre-configured masking engine."""
    return DataMaskingEngine(masking_level=level)


def mask_dataset(
    data: List[Dict[str, Any]], 
    column_types: Dict[str, str],
    masking_level: MaskingLevel = MaskingLevel.STANDARD
) -> List[Dict[str, Any]]:
    """Mask entire dataset."""
    engine = create_masking_engine(masking_level)
    
    masked_data = []
    for row in data:
        masked_row = engine.mask_row_data(row, column_types)
        masked_data.append(masked_row)
    
    return masked_data


def analyze_dataset_sensitivity(
    data: List[Dict[str, Any]], 
    column_types: Dict[str, str]
) -> Dict[str, Any]:
    """Analyze dataset for sensitive data."""
    engine = create_masking_engine()
    
    analysis = {
        'total_columns': len(column_types),
        'sensitive_columns': 0,
        'column_analysis': {},
        'overall_sensitivity': 0.0,
        'recommendations': []
    }
    
    # Analyze each column
    for column_name, data_type in column_types.items():
        # Get sample values
        sample_values = [row.get(column_name) for row in data[:100] if row.get(column_name) is not None]
        
        column_analysis = engine.analyze_column_sensitivity(
            column_name, data_type, sample_values
        )
        
        analysis['column_analysis'][column_name] = column_analysis
        
        if column_analysis['is_sensitive']:
            analysis['sensitive_columns'] += 1
            analysis['recommendations'].append({
                'column': column_name,
                'strategy': column_analysis['recommended_strategy'],
                'categories': column_analysis['data_categories']
            })
    
    # Calculate overall sensitivity
    if analysis['total_columns'] > 0:
        analysis['overall_sensitivity'] = analysis['sensitive_columns'] / analysis['total_columns']
    
    return analysis


# CLI interface for data masking
if __name__ == "__main__":
    import json
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python data_masking.py <command> [args...]")
        print("Commands: mask, analyze, test")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "test":
        # Test masking engine
        engine = create_masking_engine(MaskingLevel.STANDARD)
        
        test_data = {
            'email': 'john.doe@example.com',
            'first_name': 'John', 
            'last_name': 'Doe',
            'phone': '555-123-4567',
            'ssn': '123-45-6789',
            'salary': 75000.00,
            'credit_card': '4532-1234-5678-9012'
        }
        
        column_types = {
            'email': 'varchar',
            'first_name': 'varchar',
            'last_name': 'varchar', 
            'phone': 'varchar',
            'ssn': 'varchar',
            'salary': 'decimal',
            'credit_card': 'varchar'
        }
        
        print("Original Data:")
        print(json.dumps(test_data, indent=2))
        
        masked_data = engine.mask_row_data(test_data, column_types)
        
        print("\nMasked Data:")
        print(json.dumps(masked_data, indent=2))
        
        print("\nMasking Statistics:")
        print(json.dumps(engine.get_masking_statistics(), indent=2))
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)