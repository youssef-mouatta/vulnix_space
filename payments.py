class PaymentService:
    PLANS = {
        'Free': {'price': 0, 'limit': 5, 'features': ['basic_scan']},
        'Pro': {'price': 7, 'limit': -1, 'features': ['basic_scan', 'pdf_export']},
        'Business': {'price': 20, 'limit': -1, 'features': ['basic_scan', 'pdf_export', 'json_export']}
    }

    CHECKOUT_LINKS = {
        'Pro': 'https://buy.stripe.com/test_pro_link_placeholder',
        'Business': 'https://buy.stripe.com/test_business_link_placeholder'
    }

    @staticmethod
    def get_checkout_link(plan_name):
        return PaymentService.CHECKOUT_LINKS.get(plan_name)

    @staticmethod
    def can_access_feature(current_plan, feature_name):
        plan_features = PaymentService.PLANS.get(current_plan, {}).get('features', [])
        return feature_name in plan_features

    @staticmethod
    def within_scan_limit(current_plan, current_scans):
        limit = PaymentService.PLANS.get(current_plan, {}).get('limit', 0)
        if limit == -1:
            return True
        return current_scans < limit
