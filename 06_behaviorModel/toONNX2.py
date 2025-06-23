import joblib 
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

model = joblib.load("behavModel.joblib");

initial_type = [('float_input',FloatTensorType([None,5]))]
onnx_model = convert_sklearn(model,initial_types=initial_type)

with open("behavModel.onnx","wb") as f:
    f.write(onnx_model.SerializeToString())


