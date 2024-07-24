package cl.niclabs.autovpn;

import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

public class PepaWorker extends Worker {

    public static transient final String TAG = "PepaWorker";
    private transient Context context;

    public PepaWorker(Context context, WorkerParameters params) {
        super(context, params);
        this.context = context;
    }

    @NonNull
    @Override
    public Result doWork() {
        //Report.saveFiles(context);
        Log.d(TAG, "PePaWorker running...");
        Intent intent = VpnService.prepare(context);
        long timestamp = System.currentTimeMillis();
        if (intent == null) {
            Log.d(TAG, "Launching AutoVPN Service...");
            Intent vpnIntent = new Intent(context, AutoVpnService.class);
            vpnIntent.putExtra(context.getString(R.string.timestamp_key), timestamp);

            context.startService(vpnIntent);
        }

        //Report.sendFiles(context);

        //Gson gson = new GsonBuilder().setPrettyPrinting().create();
        //Log.i("JSONData", gson.toJson(Reader.readJSONFile(context, dataFile)));
        return Result.success();
    }
}
