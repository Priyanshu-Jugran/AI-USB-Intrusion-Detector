import joblib 
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

model = joblib.load("bestAIModel.joblib");

initial_type = [('float_input',FloatTensorType([None,3]))]
onnx_model = convert_sklearn(model,initial_types=initial_type)

with open("bestAIModel.onnx","wb") as f:
    f.write(onnx_model.SerializeToString())


