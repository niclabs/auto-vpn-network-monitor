package cl.niclabs.autovpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

public class BatteryHelperFragment extends Fragment {
    private static final Intent[] POWERMANAGER_INTENTS = {
            new Intent().setComponent(new ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")),
            new Intent().setComponent(new ComponentName("com.letv.android.letvsafe", "com.letv.android.letvsafe.AutobootManageActivity")),
            new Intent().setComponent(new ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")),
            new Intent().setComponent(new ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity")),
            new Intent().setComponent(new ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity")),
            new Intent().setComponent(new ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity")),
            new Intent().setComponent(new ComponentName("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity")),
            new Intent().setComponent(new ComponentName("com.oppo.safe", "com.oppo.safe.permission.startup.StartupAppListActivity")),
            new Intent().setComponent(new ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity")),
            new Intent().setComponent(new ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager")),
            new Intent().setComponent(new ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity")),
            new Intent().setComponent(new ComponentName("com.samsung.android.lool", "com.samsung.android.sm.ui.battery.BatteryActivity")),
            new Intent().setComponent(new ComponentName("com.htc.pitroad", "com.htc.pitroad.landingpage.activity.LandingPageActivity")),
            new Intent().setComponent(new ComponentName("com.asus.mobilemanager", "com.asus.mobilemanager.MainActivity"))
    };


    public static final String TAG = "BatteryFragment";
    private Context context;
    private MainActivity activity;
    private int BATTERY_REQUEST_CODE = 0;
    private int POWER_REQUEST_CODE = 1;
    private int MANUAL_BATTERY_POWER_REQUEST = 2;

    public BatteryHelperFragment() {

    }

    public static BatteryHelperFragment newInstance() {
        return new BatteryHelperFragment();
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
        disableBatteryOptimizations();
    }

    @Override
    public void onDetach() {
        super.onDetach();
        this.context = null;
        this.activity = null;
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == BATTERY_REQUEST_CODE) {
            if (resultCode != Activity.RESULT_OK)
                activity.closeNow();
            else
                disablePowerOptimizations();
        } else if (requestCode == POWER_REQUEST_CODE) {
            try {
                Intent intent = new Intent();
                intent.setClassName("com.miui.powerkeeper",
                        "com.miui.powerkeeper.ui.HiddenAppsConfigActivity");
                intent.putExtra("package_name", "cl.niclabs.vpnpassiveping");
                intent.putExtra("package_label", getText(R.string.app_name));
                startActivityForResult(intent, MANUAL_BATTERY_POWER_REQUEST);
            } catch (ActivityNotFoundException anfe) {
                //((SettingsActivity) activity).vpnEnabled();
            }
        } else if (requestCode == MANUAL_BATTERY_POWER_REQUEST) {
            //((SettingsActivity) activity).vpnEnabled();
        }
    }

    private void disableBatteryOptimizations() {
        Intent intent = new Intent();
        String packageName = context.getPackageName();
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        Log.d("BATTERY START","BATTERY");

        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            intent.setAction(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
            intent.setData(Uri.parse("package:" + packageName));
            startActivityForResult(intent, BATTERY_REQUEST_CODE);
        } else
            disablePowerOptimizations();
    }

    private void disablePowerOptimizations() {
        boolean found = false;
        for (final Intent powerIntent : POWERMANAGER_INTENTS) {
            if (activity.getPackageManager().resolveActivity(powerIntent, PackageManager.MATCH_DEFAULT_ONLY) != null) {
                found = true;
                AlertDialog alertDialog = new AlertDialog.Builder(activity)
                        .setTitle("Permitir ejecución en 2do plano")
                        .setMessage("Por favor permite que la app se ejecute en segundo plano :)")

                        // Specifying a listener allows you to take an action before dismissing the dialog.
                        // The dialog is automatically dismissed when a dialog button is clicked.
                        .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                startActivityForResult(powerIntent, POWER_REQUEST_CODE);
                            }
                        })
                        .setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                activity.closeNow();
                            }
                        })
                        .setIcon(android.R.drawable.ic_dialog_alert)
                        .create();
                alertDialog.show();
                break;
            }
        }
        //if (!found && activity instanceof SettingsActivity)
        //    ((SettingsActivity) activity).vpnEnabled();
    }
}
