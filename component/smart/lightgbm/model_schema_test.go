package lightgbm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func appendModelTransforms(t *testing.T, path, order, definitions string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = fmt.Fprintf(file, "[transforms]\n[order]\n%s[/order]\n[definitions]\n%s[/definitions]\ntransform=true\n[/transforms]\n", order, definitions)
	closeErr := file.Close()
	require.NoError(t, err)
	require.NoError(t, closeErr)
}

func TestPredictionUsesModelsCategoricalSchema(t *testing.T) {
	input := &smart.ModelInput{Success: 10, DestIPASN: "Google", Host: "example.com", DestPort: 443}
	for _, tc := range []struct {
		count           int
		want            float64
		scale           float64
		wantTransformed float64
	}{{30, 1, 0.01, 2}, {32, 2, 100, 1}} {
		t.Run(fmt.Sprint(tc.count), func(t *testing.T) {
			model := &WeightModel{}
			path := writeSchemaModel(t, tc.count)
			require.NoError(t, model.loadModel(path))
			weight, predicted := model.PredictWeight(input, 1)
			require.True(t, predicted)
			require.Equal(t, tc.want, weight)
			var order strings.Builder
			for i := 0; i < tc.count; i++ {
				fmt.Fprintf(&order, "%d=%s\n", i, defaultFeatureOrder[i])
			}
			appendModelTransforms(t, path, order.String(), fmt.Sprintf("std_type=StandardScaler\nstd_features=19\nstd_mean=0\nstd_scale=%g\n", tc.scale))
			require.NoError(t, model.loadModel(path))
			require.True(t, model.transforms.TransformsEnabled)
			require.Len(t, model.transforms.FeatureOrder, tc.count)
			require.True(t, model.transforms.compatibleWith(tc.count))
			weight, predicted = model.PredictWeight(input, 1)
			require.True(t, predicted)
			require.Equal(t, tc.wantTransformed, weight, "both models must load and apply their scaler")
			model.transforms.FeatureOrder[19] = "wrong_slot"
			_, predicted = model.PredictWeight(input, 1)
			require.False(t, predicted, "incompatible transforms must use traditional weights")
		})
	}
}

func TestModelTransformsUseModelFeatureCount(t *testing.T) {
	for _, count := range []int{30, 32} {
		for _, order := range []struct {
			name, content string
		}{{"default_order", ""}, {"partial_order", "19=asn_feature\n"}} {
			t.Run(fmt.Sprintf("%d/%s", count, order.name), func(t *testing.T) {
				path := writeSchemaModel(t, count)
				appendModelTransforms(t, path, order.content, "robust_type=RobustScaler\nrobust_features=19\nrobust_center=0\nrobust_scale=100\n")
				model := &WeightModel{}
				require.NoError(t, model.loadModel(path))
				require.True(t, model.transforms.TransformsEnabled)
				require.Len(t, model.transforms.FeatureOrder, count)
				weight, predicted := model.PredictWeight(&smart.ModelInput{Success: 10, DestIPASN: "Google"}, 1)
				require.True(t, predicted)
				require.Equal(t, float64(1), weight)
				originalName := defaultFeatureOrder[19]
				t.Cleanup(func() { defaultFeatureOrder[19] = originalName })
				model.transforms.FeatureOrder[19] = "wrong_slot"
				require.Equal(t, "asn_feature", defaultFeatureOrder[19], "parsed orders must not share the default map")
			})
		}
	}
}

func TestModelRejectsIncompatibleTransforms(t *testing.T) {
	for _, tc := range []struct {
		name        string
		count       int
		order       string
		definitions string
		wantError   string
	}{
		{"legacy_wrong_order", 30, "19=wrong_slot\n", "", "model feature order"},
		{"current_wrong_order", 32, "19=wrong_slot\n", "", "model feature order"},
		{"legacy_extra_slots", 30, "30=exit_region\n31=exit_asn_hash\n", "", "model feature order"},
		{"legacy_out_of_range_scaler", 30, "", "std_type=StandardScaler\nstd_features=30\nstd_mean=0\nstd_scale=1\n", "out of range"},
		{"invalid_scaler_parameters", 32, "", "std_type=StandardScaler\nstd_features=19,20\nstd_mean=0\nstd_scale=1,1\n", "mean parameter count mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSchemaModel(t, tc.count)
			appendModelTransforms(t, path, tc.order, tc.definitions)
			model := &WeightModel{}
			require.ErrorContains(t, model.loadModel(path), tc.wantError)
			require.Nil(t, model.model)
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
