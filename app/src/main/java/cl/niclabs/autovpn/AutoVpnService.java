package cl.niclabs.autovpn;

import static android.os.Process.INVALID_UID;
import static android.system.OsConstants.IPPROTO_IP;
import static android.system.OsConstants.IPPROTO_TCP;
import static android.system.OsConstants.IPPROTO_UDP;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;
import androidx.work.Constraints;
import androidx.work.ExistingWorkPolicy;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class AutoVpnService extends VpnService implements Runnable {
    private static final String TAG = "AutoVpnService";
    private ParcelFileDescriptor mInterface;

    private static boolean isJniRunning;
    private long timestamp;
    private Thread mThread;
    public native int startVPN(int fd, long timestamp);

    public static native int endVPN();

    static {
        System.loadLibrary("auto_vpn_jni");
    }

    @Override
    public void onCreate() {
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        isJniRunning = false;
        Log.d(TAG, "AutoVPN Service started");
        try {
            this.timestamp = intent.getLongExtra("timestamp", -1);
            createVpnNotification();

            // Stop the previous session by interrupting the thread.
            if (mThread != null) {
                mThread.interrupt();
            }

            // Start a new session by creating a new thread.
            mThread = new Thread(this, TAG);
            mThread.start();
            return START_REDELIVER_INTENT;
        } catch (NullPointerException e) {
            stopSelf();
            return START_NOT_STICKY;
        }
    }

    private void createVpnNotification() {
        final String CHANNEL_ID = "ForegroundServiceChannel";

        NotificationChannel serviceChannel = new NotificationChannel(
                CHANNEL_ID,
                "Foreground Service Channel",
                NotificationManager.IMPORTANCE_LOW
        );

        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(serviceChannel);

        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this,
                0, notificationIntent, PendingIntent.FLAG_IMMUTABLE);


        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Monitoring the network...")
                .setContentIntent(pendingIntent)
                .setVibrate(new long[]{0L})
                .build();

        startForeground(1, notification);
    }


    @Override
    public void run() {
        boolean connected = configure();
        //this.environment = new Environment(getApplicationContext());
        //this.environment.setTimestamp(this.timestamp);

        if (connected) {

            setAlarm();

            isJniRunning = true;

            //registerConnectivityReceiver();
            startVPN(mInterface.detachFd(), this.timestamp);
            closeVpnConnection();
        }
    }

    private boolean configure() {
        Builder builder = new Builder();

        String appName = getApplicationContext().getPackageName();
        try {
            builder.addDisallowedApplication(appName);
        } catch (PackageManager.NameNotFoundException e) {
            Log.d(TAG, "addDisallowed didn't find " + appName);
        }


        boolean v4State = false;
        try {
            String address = getLocalIpAddress(); //IPv4 Address
            if (address != null) {
                builder.addAddress(address, 32);
                builder.addRoute("0.0.0.0", 0);
                v4State = true;
            }
            if (v4State) {
                Log.i(TAG, "IPv4 supported " + address);
                this.mInterface = builder.establish();
            } else {
                Log.i(TAG, "Couldn't get v4 address. v6 not available, or not supported on your phone");
            }
            if (this.mInterface == null) {
                Log.e(TAG, "Error establishing VPN connection. VPN interface is null");
                stopSelf();
                return false;
            }
            return v4State;

        } catch (Exception e1) {
            Log.e(TAG, "Error creating localhost: " + e1.getMessage(), e1);
        }
        return false;
    }

    public synchronized void closeVpnConnection() {
        Log.i(TAG, "running " + isJniRunning);

        if (isJniRunning) {
            //unregisterConnectivityReceiver();
            //environment.logLoc(); //see data saved

            try {
                if (mInterface != null) {
                    mInterface.close();
                    mInterface = null;
                }
            } catch (Exception e) {
                Log.e("CloseVPN", e.toString());
            }
            isJniRunning = false;
            stopSelf();
            endVPN();
            final Context context = getApplicationContext();

           // environment.save();

            //Report.sendFiles(context);
        }
    }


    public static String getLocalIpAddress() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            Log.d(TAG, "IP: " + interfaces.size());

            for (NetworkInterface networkInterface : interfaces) {

                List<InetAddress> addresses = Collections.list(networkInterface.getInetAddresses());
                Log.d(TAG, "IP: " + addresses.size());
                for (InetAddress inetAddress : addresses) {
                    Log.d(TAG, "IP: " + inetAddress.getHostAddress());
                    if (!inetAddress.isLoopbackAddress() && !inetAddress.isAnyLocalAddress() && !inetAddress.isLinkLocalAddress()) {
                        Log.d(TAG, "IP: " + inetAddress.getHostAddress());

                        if (inetAddress instanceof Inet4Address) {
                            return inetAddress.getHostAddress();
                        }
                    }
                }
            }
        } catch (SocketException ex) {
            Log.e(TAG, ex.getMessage(), ex);
        }
        return null;
    }

    private void setAlarm() {
        Constraints constraints = new Constraints.Builder()
                .setRequiresBatteryNotLow(false)
                .setRequiresCharging(false)
                .setRequiresDeviceIdle(false)
                .setRequiresStorageNotLow(false)
                .build();

        final OneTimeWorkRequest workRequest = new OneTimeWorkRequest.Builder(AlarmWorker.class)
                .addTag(AlarmWorker.TAG)
                .setConstraints(constraints)
                .setInitialDelay(5*60, TimeUnit.SECONDS)
                .build();

        final WorkManager workManager = WorkManager.getInstance(this);
        workManager.enqueueUniqueWork(AlarmWorker.TAG,
                ExistingWorkPolicy.REPLACE,
                workRequest);
    }

    public String getOwnerApplication(String protocol, String srcIp, int srcPort, String dstIp, int dstPort) {
        InetSocketAddress src = new InetSocketAddress(srcIp, srcPort);
        InetSocketAddress dst = new InetSocketAddress(dstIp, dstPort);

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        int ipProto = IPPROTO_IP;
        if (protocol.equals("tcp"))
            ipProto = IPPROTO_TCP;
        else if (protocol.equals("udp"))
            ipProto = IPPROTO_UDP;

        int uid = connectivityManager.getConnectionOwnerUid(ipProto, src, dst);

        if (uid != INVALID_UID) {
            return getPackageName(uid);
        }
        return "";
    }

    public String getPackageName(int uid) {
        PackageManager pm = getPackageManager();
        String[] packages = pm.getPackagesForUid(uid);
        if (packages != null && packages.length > 0) {
            Log.d(TAG, "package: " + packages[0] + " for uid " + uid);
            return packages[0];
        }
        Log.d(TAG, "package: not found for uid +" + uid);
        return Integer.toString(uid);
    }
}
