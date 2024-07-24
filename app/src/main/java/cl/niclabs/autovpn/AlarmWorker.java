package cl.niclabs.autovpn;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

public class AlarmWorker extends Worker {
    public static transient final String TAG = "AlarmWorker";

    public AlarmWorker(Context context, WorkerParameters params) {
        super(context, params);
    }

    @Override
    @NonNull
    public Result doWork() {
        AutoVpnService.endVPN();
        Log.d(TAG, "end VPN");
        return Result.success();
    }

}
