package cl.niclabs.autovpn;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.preference.PreferenceManager;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.core.app.ActivityCompat;
import androidx.fragment.app.Fragment;

import java.util.ArrayList;
import java.util.List;

public class PermissionsHelperFragment extends Fragment {
    private static final int MULTIPLE_PERMISSIONS = 10;
    public static final String TAG = "PermissionsFragment";
    private final String[] permissions = new String[]{
            android.Manifest.permission.ACCESS_COARSE_LOCATION,
            android.Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.READ_PHONE_STATE,
    };
    private Context context;
    private MainActivity activity;

    public PermissionsHelperFragment() {

    }

    public static PermissionsHelperFragment newInstance() {
        return new PermissionsHelperFragment();
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setRetainInstance(true);
    }

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);
        this.context = context;
        if (context instanceof Activity) {
            this.activity = (MainActivity) context;
        }
        checkPermissions();
    }

    @Override
    public void onDetach() {
        super.onDetach();
        this.context = null;
    }

    private ActivityResultLauncher<String[]> requestPermissionLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), grantResults -> {
                if (grantResults.containsValue(false)) {
                    // Permission is granted. Continue the action or workflow in your
                    // app.
                    checkPermissions();
                } else {
                    // Explain to the user that the feature is unavailable because the
                    // feature requires a permission that the user has denied. At the
                    // same time, respect the user's decision. Don't link to system
                    // settings in an effort to convince the user to change their
                    // decision.
                    activity.loadBatteryFragment();
                }
            });


    public boolean checkPermissions() {
        int result;
        List<String> listPermissionsNeeded = new ArrayList<>();
        for (String p : permissions) {
            result = ActivityCompat.checkSelfPermission(context, p);
            if (result != PackageManager.PERMISSION_GRANTED) {
                listPermissionsNeeded.add(p);
            }
        }
        if (!listPermissionsNeeded.isEmpty()) {
            //requestPermissions(listPermissionsNeeded.toArray(new String[0]), MULTIPLE_PERMISSIONS);
            requestPermissionLauncher.launch(listPermissionsNeeded.toArray(new String[0]));
            return false;
        }

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        //boolean vpnStarted = prefs.getBoolean(getString(R.string.pref_vpn_started_key), false);
        //if (!vpnStarted)
        activity.loadBatteryFragment();
        return true;
    }

}
