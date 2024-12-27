<script setup lang="ts">

import UserInfo from "@/components/UserInfo.vue";

</script>

<template>
  <main>
    <Suspense>
      <UserInfo />
    </Suspense>
  </main>
</template>
