importScripts('https://www.gstatic.com/firebasejs/11.5.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/11.5.0/firebase-messaging-compat.js');

// Initialize Firebase
firebase.initializeApp({
    apiKey: "AIzaSyBDxxjL2nNRI501bWaaod6-ZI3lbQRsAJM",
    authDomain: "roi-donate.firebaseapp.com",
    projectId: "roi-donate",
    storageBucket: "roi-donate.firebasestorage.app",
    messagingSenderId: "1082376703847",
    appId: "1:1082376703847:web:097837845bfdd885c869c2",
    measurementId: "G-NCN9WX68S2"
});

const messaging = firebase.messaging();

// Handle background messages
messaging.onBackgroundMessage((payload) => {
    console.log('Background message received:', payload);

    const notificationTitle = payload.notification.title;
    const notificationOptions = {
        body: payload.notification.body,
        icon: '/static/images/logo.png',
        badge: '/static/images/logo.png',
        data: payload.data
    };

    return self.registration.showNotification(notificationTitle, notificationOptions);
}); 