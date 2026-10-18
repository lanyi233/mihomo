package lightgbm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/smart"
	"github.com/stretchr/testify/require"
)

func writeSchemaModel(t *testing.T, count int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Model.bin")
	// The categorical encoding changed from Google=1 to Google=100. A stump
	// on that slot detects using the wrong schema even when lengths match.
	model := fmt.Sprintf("tree\nversion=v3\nnum_class=1\nnum_tree_per_iteration=1\nmax_feature_idx=%d\nobjective=regression\ntree_sizes=1\n\nTree=0\nnum_leaves=2\nnum_cat=0\nsplit_feature=19\nthreshold=50\ndecision_type=2\nleft_child=-1\nright_child=-2\nleaf_value=1 2\n\n", count-1)
	require.NoError(t, os.WriteFile(path, []byte(model), 0o600))
	return path
}

func TestPredictionUsesModelsCategoricalSchema(t *testing.T) {
	input := &smart.ModelInput{Success: 10, DestIPASN: "Google", Host: "example.com", DestPort: 443}
	for _, tc := range []struct {
		count int
		want  float64
	}{{30, 1}, {32, 2}} {
		t.Run(fmt.Sprint(tc.count), func(t *testing.T) {
			model := &WeightModel{}
			require.NoError(t, model.loadModel(writeSchemaModel(t, tc.count)))
			weight, predicted := model.PredictWeight(input, 1)
			require.True(t, predicted)
			require.Equal(t, tc.want, weight)
			order := make(map[int]string, tc.count)
			for i := 0; i < tc.count; i++ {
				order[i] = defaultFeatureOrder[i]
			}
			model.transforms = &FeatureTransforms{
				TransformsEnabled: true, FeatureOrder: order,
				Transforms: []TransformParams{{
					Type: StandardScalerTransform, FeatureIndices: []int{19},
					Parameters: map[string][]float64{"mean": {0}, "scale": {100}},
				}},
			}
			require.True(t, model.transforms.compatibleWith(tc.count))
			weight, predicted = model.PredictWeight(input, 1)
			require.True(t, predicted)
			require.Equal(t, float64(1), weight, "both models must apply their scaler")
			model.transforms.FeatureOrder[19] = "wrong_slot"
			_, predicted = model.PredictWeight(input, 1)
			require.False(t, predicted, "incompatible transforms must use traditional weights")
		})
	}
}

func TestUnknownModelSchemaUsesTraditionalWeights(t *testing.T) {
	model := &WeightModel{}
	require.NoError(t, model.loadModel(writeSchemaModel(t, 31)))
	input := &smart.ModelInput{Success: 10, IsTCP: true, ConnectTime: 50, Latency: 50}
	weight, predicted := model.PredictWeight(input, 1)
	want, _ := smart.CalculateWeight(input, 1)
	require.False(t, predicted)
	require.Equal(t, want, weight)
}

func TestLegacyProviderEncodingIsStableForAmbiguousDescriptions(t *testing.T) {
	for range 100 {
		require.Equal(t, 6, legacyExtractASNFeature("Google via Cloudflare"))
		require.Equal(t, 2, legacyExtractASNFeature("Google via Amazon"))
	}
}
