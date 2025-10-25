from client.log_processor import EvaluationLogProcessor

import json
import matplotlib
import numpy

if __name__ == "__main__":
    processor = EvaluationLogProcessor()
    processor.process_test_log("saml", 300, 10)
    #fetch_and_store_log("saml", 300, 10)
    #serialize_saml_log_into_json(
    #    f"{client_secrets.LOG_STORAGE_PATH}/saml-eval-300-10-1.log"
    #    )