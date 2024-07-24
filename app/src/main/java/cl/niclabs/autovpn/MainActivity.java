package cl.niclabs.autovpn;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.work.Constraints;
import androidx.work.ExistingWorkPolicy;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import cl.niclabs.autovpn.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

public boolean vpnStarted;
private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Check VPN permission
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            VpnRequestResultLauncher.launch(intent);
        }
    }

    ActivityResultLauncher<Intent> VpnRequestResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        loadHelperFragments();
                    } else if (result.getResultCode() == Activity.RESULT_CANCELED) {
                        Toast.makeText(getApplicationContext(), getString(R.string.request_vpn_permission_text), Toast.LENGTH_LONG).show();
                        new Handler().postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                closeNow();                    }
                        }, 2000);

                    }
                }
            });

    public void onClickButton(View view) {
        Button startButton = findViewById(R.id.start_button);
        //startButton.setEnabled(false);
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            VpnRequestResultLauncher.launch(intent);
        } else {
            vpnEnabled();
        }
    }

    public void vpnEnabled() {
        this.vpnStarted = true;
        Toast.makeText(this, R.string.starting_text, Toast.LENGTH_LONG).show();
        runWorker();
    }

    public void runWorker() {
        Constraints constraints = new Constraints.Builder()
                .setRequiresBatteryNotLow(false)
                .setRequiresCharging(false)
                .setRequiresDeviceIdle(false)
                .setRequiresStorageNotLow(false)
                .build();
        final OneTimeWorkRequest workRequest = new OneTimeWorkRequest.Builder(PepaWorker.class)
                .addTag(PepaWorker.TAG)
                .setConstraints(constraints)
                .build();

        final WorkManager workManager = WorkManager.getInstance(getApplicationContext());
        workManager.enqueueUniqueWork(PepaWorker.TAG,
                ExistingWorkPolicy.REPLACE,
                workRequest);
    }

    public void closeNow() {
        this.finishAffinity();
        System.exit(0);
    }

    public void loadHelperFragments() {
        loadPermissionsFragment();
    }

    public void loadPermissionsFragment() {
        addFragmentByTag(PermissionsHelperFragment.newInstance(), PermissionsHelperFragment.TAG);
    }

    public void loadBatteryFragment() {
        addFragmentByTag(BatteryHelperFragment.newInstance(), BatteryHelperFragment.TAG);
    }

    public void addFragmentByTag(Fragment fragment, String TAG) {
        Fragment f = getSupportFragmentManager().findFragmentByTag(TAG);
        if (f == null) {
            getSupportFragmentManager().beginTransaction()
                    .add(fragment, TAG)
                    .commit();
        }
    }

}