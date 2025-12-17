import ember
import lightgbm as lgb

class EmberDetector:
    def __init__(self, model_path):
        self.model = lgb.Booster(model_file=model_path)

    def score(self, pe_bytes):
        return ember.predict_sample(self.model, pe_bytes)