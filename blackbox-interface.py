import ember
import lightgbm as lgb
import sys

sha256 = sys.argv[1]

lgbm_model = lgb.Booster(model_file="weight-ember.txt")
putty_data = open(f"malwares/{sha256}.exe", "rb").read()
print(ember.predict_sample(lgbm_model, putty_data))